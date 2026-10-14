package validate_test

// Small test helpers mirrored from the root tests (contains, boolPtr) so the validate tests
// stand alone in their package.

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func boolPtr(b bool) *bool { return &b }
