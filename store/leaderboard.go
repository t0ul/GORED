package store

import (
	"math"
	"sort"
)

// LeaderboardRow is the aggregate for one (model, skill_temp, difficulty) cell: the
// capture rate with its sample size and standard error, and the efficiency medians
// among captures (plan §7/§8). Efficiency is reported over successful runs only,
// since tool-call and wall-time counts are meaningful only when a flag was taken.
type LeaderboardRow struct {
	Model           string
	SkillTemp       string
	Difficulty      string
	N               int
	Captured        int
	CaptureRate     float64 // Captured / N
	StdErr          float64 // sqrt(p(1-p)/N): the variance of the rate
	MedianToolCalls int     // among captures
	MedianWallMS    int     // among captures
}

type runRow struct {
	model, skillTemp, difficulty, outcome string
	toolCalls, wallMS                     int
}

func (s *Store) allRuns() ([]runRow, error) {
	rows, err := s.db.Query(`SELECT model, COALESCE(skill_temp,''), COALESCE(difficulty,''), COALESCE(outcome,''), COALESCE(tool_calls,0), COALESCE(wall_ms,0) FROM redteam_runs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runRow
	for rows.Next() {
		var r runRow
		if err := rows.Scan(&r.model, &r.skillTemp, &r.difficulty, &r.outcome, &r.toolCalls, &r.wallMS); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Leaderboard aggregates all persisted runs into per-cell rows, sorted by capture
// rate (desc), then model, skill temperature, and difficulty.
func (s *Store) Leaderboard() ([]LeaderboardRow, error) {
	runs, err := s.allRuns()
	if err != nil {
		return nil, err
	}
	type key struct{ model, temp, diff string }
	groups := map[key][]runRow{}
	var order []key
	for _, r := range runs {
		k := key{r.model, r.skillTemp, r.difficulty}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r)
	}
	var out []LeaderboardRow
	for _, k := range order {
		g := groups[k]
		var captured int
		var tcs, walls []int
		for _, r := range g {
			if r.outcome == "captured" {
				captured++
				tcs = append(tcs, r.toolCalls)
				walls = append(walls, r.wallMS)
			}
		}
		n := len(g)
		p := 0.0
		if n > 0 {
			p = float64(captured) / float64(n)
		}
		out = append(out, LeaderboardRow{
			Model: k.model, SkillTemp: k.temp, Difficulty: k.diff,
			N: n, Captured: captured, CaptureRate: p,
			StdErr:          math.Sqrt(p * (1 - p) / float64(max1(n))),
			MedianToolCalls: medianInt(tcs),
			MedianWallMS:    medianInt(walls),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CaptureRate != out[j].CaptureRate {
			return out[i].CaptureRate > out[j].CaptureRate
		}
		if out[i].Model != out[j].Model {
			return out[i].Model < out[j].Model
		}
		if out[i].SkillTemp != out[j].SkillTemp {
			return out[i].SkillTemp < out[j].SkillTemp
		}
		return out[i].Difficulty < out[j].Difficulty
	})
	return out, nil
}

// Lift is the cold→warm capture-rate lift for one (model, difficulty): how much the
// warm scaffold adds over cold. It is the headline per-model measurement (plan §8).
type Lift struct {
	Model      string
	Difficulty string
	ColdRate   float64
	WarmRate   float64
	Lift       float64 // WarmRate - ColdRate
	NCold      int
	NWarm      int
}

// ColdWarmLift computes the lift per (model, difficulty) from the persisted runs.
func (s *Store) ColdWarmLift() ([]Lift, error) {
	rows, err := s.Leaderboard()
	if err != nil {
		return nil, err
	}
	type key struct{ model, diff string }
	type acc struct {
		coldRate, warmRate float64
		nCold, nWarm       int
		haveCold, haveWarm bool
	}
	m := map[key]*acc{}
	var order []key
	for _, r := range rows {
		k := key{r.Model, r.Difficulty}
		a, ok := m[k]
		if !ok {
			a = &acc{}
			m[k] = a
			order = append(order, k)
		}
		switch r.SkillTemp {
		case "cold":
			a.coldRate, a.nCold, a.haveCold = r.CaptureRate, r.N, true
		case "warm":
			a.warmRate, a.nWarm, a.haveWarm = r.CaptureRate, r.N, true
		}
	}
	var out []Lift
	for _, k := range order {
		a := m[k]
		if !a.haveCold || !a.haveWarm {
			continue // lift needs both arms
		}
		out = append(out, Lift{
			Model: k.model, Difficulty: k.diff,
			ColdRate: a.coldRate, WarmRate: a.warmRate, Lift: a.warmRate - a.coldRate,
			NCold: a.nCold, NWarm: a.nWarm,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Lift != out[j].Lift {
			return out[i].Lift > out[j].Lift
		}
		return out[i].Model < out[j].Model
	})
	return out, nil
}

func medianInt(xs []int) int {
	if len(xs) == 0 {
		return 0
	}
	sort.Ints(xs)
	n := len(xs)
	if n%2 == 1 {
		return xs[n/2]
	}
	return (xs[n/2-1] + xs[n/2]) / 2
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
