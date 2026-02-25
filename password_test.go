package password

import (
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	pw := "testpassword123"
	hash := Generate(pw)

	if hash == "" {
		t.Error("Generate() returned empty string")
	}

	// The hash should be different from the original password
	if hash == pw {
		t.Error("Generate() returned the original password instead of a hash")
	}

	// Check hash format
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Errorf("Invalid hash format: %s", hash)
	}

	// Each call should produce a different hash (due to random salt)
	hash2 := Generate(pw)
	if hash == hash2 {
		t.Error("Generate() should produce different hashes for the same password")
	}
}

func TestGenerate_Empty(t *testing.T) {
	hash := Generate("")
	if hash != "" {
		t.Error("Generate() should handle empty passwords")
	}
}

func TestVerify(t *testing.T) {
	pw := "mysecretpassword"
	hash := Generate(pw)

	valid, err := Verify(pw, hash)
	if err != nil {
		t.Errorf("Verify() returned error: %v", err)
	}
	if !valid {
		t.Error("Verify() failed to validate correct password")
	}
}

func TestVerify_WrongPassword(t *testing.T) {
	pw := "mysecretpassword"
	hash := Generate(pw)

	valid, err := Verify("wrongpassword", hash)
	if err != nil {
		t.Errorf("Verify() returned error: %v", err)
	}
	if valid {
		t.Error("Verify() incorrectly validated wrong password")
	}
}

func TestVerify_EmptyInputs(t *testing.T) {
	hash := Generate("testpassword")

	// Empty password
	valid, _ := Verify("", hash)
	if valid {
		t.Error("Verify() should return false for empty password")
	}

	// Empty hash
	valid, _ = Verify("password", "")
	if valid {
		t.Error("Verify() should return false for empty hash")
	}

	// Both empty
	valid, _ = Verify("", "")
	if valid {
		t.Error("Verify() should return false when both inputs are empty")
	}
}

func TestVerify_InvalidHash(t *testing.T) {
	invalidHashes := []string{
		"not_a_hash",
		"$argon2id",
		"$argon2id$v=19$m=notanumber",
		"$argon2id$v=invalid$",
	}

	for _, h := range invalidHashes {
		_, err := Verify("password", h)
		if err == nil {
			t.Errorf("Verify() should return error for invalid hash: %s", h)
		}
	}
}

func TestGenerateAndVerify_Roundtrip(t *testing.T) {
	passwords := []string{
		"simple",
		"complex!@#$%^&*()_+",
		"unicode世界",
		"a" + strings.Repeat("verylong", 100),
	}

	for _, pw := range passwords {
		hash := Generate(pw)
		valid, err := Verify(pw, hash)
		if err != nil {
			t.Errorf("Verify() error for password %q: %v", pw, err)
		}
		if !valid {
			t.Errorf("Verify() failed for password %q", pw)
		}

		// Verify wrong password doesn't match
		valid, _ = Verify(pw+"x", hash)
		if valid {
			t.Errorf("Verify() incorrectly validated modified password for %q", pw)
		}
	}
}
