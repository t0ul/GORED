package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// Manifest describes a target: its name, an optional base URL where it runs, and
// the flags planted in it. Real target manifests (for the author's own apps) are
// private and live under targets/ (gitignored); the only tracked manifest is the
// benign demo target's.
type Manifest struct {
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	BaseURL     string     `json:"base_url,omitempty"`
	Flags       []FlagSpec `json:"flags"`
}

// LoadManifest reads and validates a manifest JSON file.
func LoadManifest(path string) (Manifest, error) {
	var m Manifest
	data, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, fmt.Errorf("gored: parse manifest %s: %w", path, err)
	}
	if err := m.Validate(); err != nil {
		return m, fmt.Errorf("gored: invalid manifest %s: %w", path, err)
	}
	return m, nil
}

// Validate checks structural invariants: a name, at least one flag, and every flag
// with a unique non-empty id and a known class and difficulty.
func (m Manifest) Validate() error {
	if m.Name == "" {
		return fmt.Errorf("manifest name is empty")
	}
	if len(m.Flags) == 0 {
		return fmt.Errorf("manifest %q has no flags", m.Name)
	}
	seen := make(map[string]bool, len(m.Flags))
	for i, f := range m.Flags {
		if f.ID == "" {
			return fmt.Errorf("flag %d has empty id", i)
		}
		if seen[f.ID] {
			return fmt.Errorf("duplicate flag id %q", f.ID)
		}
		seen[f.ID] = true
		if !validClass(f.Class) {
			return fmt.Errorf("flag %q has unknown class %q", f.ID, f.Class)
		}
		if !validDifficulty(f.Difficulty) {
			return fmt.Errorf("flag %q has unknown difficulty %q", f.ID, f.Difficulty)
		}
	}
	return nil
}

func validClass(c VulnClass) bool {
	switch c {
	case ClassIDOR, ClassSSRF, ClassAuthBypass, ClassInjection:
		return true
	}
	return false
}

func validDifficulty(d Difficulty) bool {
	switch d {
	case DiffEasy, DiffMedium, DiffHard:
		return true
	}
	return false
}
