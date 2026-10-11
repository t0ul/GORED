package gored

import "testing"

func specs() []FlagSpec {
	return []FlagSpec{
		{ID: "a", Class: ClassIDOR, Difficulty: DiffEasy},
		{ID: "b", Class: ClassSSRF, Difficulty: DiffMedium},
	}
}

func TestOracleSecretsAreUniqueUnforgeable(t *testing.T) {
	o, err := NewOracle(specs())
	if err != nil {
		t.Fatal(err)
	}
	sa, _ := o.Secret("a")
	sb, _ := o.Secret("b")
	if sa == "" || sb == "" || sa == sb {
		t.Fatalf("secrets must be non-empty and distinct, got %q %q", sa, sb)
	}
	// A fresh oracle mints different secrets — flags are per-run.
	o2, _ := NewOracle(specs())
	sa2, _ := o2.Secret("a")
	if sa == sa2 {
		t.Fatal("two oracles minted the same secret; not random per run")
	}
}

func TestDisclosedIsAuthoritative(t *testing.T) {
	o, _ := NewOracle(specs())
	if o.Captured("a") {
		t.Fatal("flag captured before any disclosure")
	}
	o.Disclosed("a", "idor:test", "served")
	if !o.Captured("a") {
		t.Fatal("Disclosed did not record capture")
	}
	c, ok := o.CaptureOf("a")
	if !ok || c.Via != "idor:test" {
		t.Fatalf("capture record wrong: %+v ok=%v", c, ok)
	}
	if o.Captured("b") {
		t.Fatal("unrelated flag captured")
	}
}

func TestSubmitRequiresExactSecret(t *testing.T) {
	o, _ := NewOracle(specs())
	if o.Submit("a", "GORED{not-the-secret}") {
		t.Fatal("wrong value captured the flag — forgeable")
	}
	if o.Captured("a") {
		t.Fatal("a wrong submission still recorded capture")
	}
	secret, _ := o.Secret("a")
	if !o.Submit("a", secret) {
		t.Fatal("correct secret did not capture")
	}
	if !o.Captured("a") {
		t.Fatal("correct submission did not record capture")
	}
}

func TestStatusHidesSecrets(t *testing.T) {
	o, _ := NewOracle(specs())
	secret, _ := o.Secret("a")
	o.Disclosed("a", "idor:test", "served")
	for _, st := range o.Status() {
		// FlagStatus has no secret field by construction; guard the Via/Evidence
		// surface too, in case someone wires the secret into the evidence later.
		if st.Via == secret {
			t.Fatal("status leaked the secret via the Via field")
		}
	}
}

func TestResetClearsAndRotates(t *testing.T) {
	o, _ := NewOracle(specs())
	old, _ := o.Secret("a")
	o.Disclosed("a", "x", "y")
	o.Reset()
	if o.Captured("a") {
		t.Fatal("Reset did not clear capture")
	}
	neu, _ := o.Secret("a")
	if old == neu {
		t.Fatal("Reset did not rotate the secret")
	}
}

func TestNewOracleRejectsBadSpecs(t *testing.T) {
	if _, err := NewOracle([]FlagSpec{{ID: ""}}); err == nil {
		t.Fatal("empty id accepted")
	}
	if _, err := NewOracle([]FlagSpec{{ID: "x"}, {ID: "x"}}); err == nil {
		t.Fatal("duplicate id accepted")
	}
}
