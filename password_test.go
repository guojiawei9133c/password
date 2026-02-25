package password

import (
	"testing"
)

// TestPasswordType tests creating a Password by direct type conversion
func TestPasswordType(t *testing.T) {
	hash := "$argon2id$v=19$m=65536,t=1,p=4$Lr27TtuSl/CAmXzbPLageA$bNemdbSgi3MtyvlnVoU1xnQ4eICpp4ObVprA1gbNDRU"
	pw := Password(hash)

	if pw.String() != hash {
		t.Errorf("Password = %q, want %q", pw.String(), hash)
	}
}

func TestPasswordType_Empty(t *testing.T) {
	pw := Password("")
	if pw.String() != "" {
		t.Errorf("Password = %q, want empty", pw.String())
	}
}

// TestVerify tests verifying plaintext password against stored hash
func TestVerify(t *testing.T) {
	// Simulate registration: hash a password
	hash := Generate("mysecretpassword")

	// Simulate login: create Password with stored hash, verify input
	pw := Password(hash)
	valid, err := pw.Verify("mysecretpassword")

	if err != nil {
		t.Errorf("Verify() returned error: %v", err)
	}
	if !valid {
		t.Error("Verify() failed to validate correct password")
	}
}

func TestVerifyWrongPassword(t *testing.T) {
	hash := Generate("mysecretpassword")
	pw := Password(hash)

	valid, err := pw.Verify("wrongpassword")
	if err != ErrPasswordMismatch {
		t.Errorf("Verify() returned error: %v", err)
	}
	if valid {
		t.Error("Verify() incorrectly validated wrong password")
	}
}

func TestVerifyEmptyInputs(t *testing.T) {
	hash := Generate("testpassword")
	pw := Password(hash)

	// Empty plaintext password
	valid, _ := pw.Verify("")
	if valid {
		t.Error("Verify() should return false for empty plaintext")
	}

	// Empty hash
	pw2 := Password("")
	valid, _ = pw2.Verify("password")
	if valid {
		t.Error("Verify() should return false for empty hash")
	}

	// Both empty
	pw3 := Password("")
	valid, _ = pw3.Verify("")
	if valid {
		t.Error("Verify() should return false when both inputs are empty")
	}
}

func TestVerifyInvalidHash(t *testing.T) {
	invalidHashes := []string{
		"not_a_hash",
		"$argon2id",
		"$argon2id$v=19$m=notanumber",
	}

	for _, h := range invalidHashes {
		pw := Password(h)
		_, err := pw.Verify("plaintext")
		if err == nil {
			t.Errorf("Verify() should return error for invalid hash: %s", h)
		}
	}
}

func TestRoundtrip(t *testing.T) {
	passwords := []string{
		"simple",
		"complex!@#$%^&*()_+",
		"unicode世界",
		"a" + "verylong" + "verylong" + "verylong" + "verylong" + "verylong",
	}

	for _, plaintext := range passwords {
		// Registration: hash the password
		hash := Generate(plaintext)

		// Login: verify
		pw := Password(hash)
		valid, err := pw.Verify(plaintext)
		if err != nil {
			t.Errorf("Verify() error for password %q: %v", plaintext, err)
		}
		if !valid {
			t.Errorf("Verify() failed for password %q", plaintext)
		}

		// Wrong password shouldn't match
		valid, _ = pw.Verify(plaintext + "x")
		if valid {
			t.Errorf("Verify() incorrectly validated modified password for %q", plaintext)
		}
	}
}

// TestGenerate tests the hash generation function
func TestGenerate(t *testing.T) {
	plaintext := "testpassword123"
	hash := Generate(plaintext)

	if hash == "" {
		t.Error("Generate() returned empty string")
	}

	// Hash should not be the same as the original password
	if hash == plaintext {
		t.Error("Generate() returned the original password instead of a hash")
	}

	// Multiple calls should produce different hashes (due to random salt)
	hash2 := Generate(plaintext)
	if hash == hash2 {
		t.Error("Generate() should produce different hashes for the same password")
	}

	// Each hash should verify correctly
	pw := Password(hash)
	valid, err := pw.Verify(plaintext)
	if err != nil || !valid {
		t.Error("Generated hash should verify correctly")
	}
}

func TestGenerateEmpty(t *testing.T) {
	hash := Generate("")
	if hash != "" {
		t.Error("Generate() should return empty string for empty password")
	}
}
