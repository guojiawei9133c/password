package password

import (
	"testing"
)

// TestGenerate tests the hash generation function
func TestGenerate(t *testing.T) {
	plaintext := "testpassword123"
	hash, err := Generate(plaintext)

	if err != nil {
		t.Errorf("Generate() returned error: %v", err)
	}
	if hash == "" {
		t.Error("Generate() returned empty string")
	}

	// Hash should not be the same as the original password
	if hash == plaintext {
		t.Error("Generate() returned the original password instead of a hash")
	}

	// Multiple calls should produce different hashes (due to random salt)
	hash2, _ := Generate(plaintext)
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
	_, err := Generate("")
	if err == nil {
		t.Error("Generate() should return error for empty password")
	}
}

func TestGenerateSaltFailure(t *testing.T) {
	// This test can't easily test rand.Read failure without mocking
	// But we document that it should return error, not panic
}

// TestPasswordType tests creating a Password by direct type conversion
func TestPasswordType(t *testing.T) {
	hash := "$argon2id$v=19$m=65536,t=1,p=4$Lr27TtuSl/CAmXzbPLageA$bNemdbSgi3MtyvlnVoU1xnQ4eICpp4ObVprA1gbNDRU"
	pw := Password(hash)

	if string(pw) != hash {
		t.Errorf("Password = %q, want %q", string(pw), hash)
	}
}

func TestPasswordType_Empty(t *testing.T) {
	pw := Password("")
	if string(pw) != "" {
		t.Errorf("Password = %q, want empty", string(pw))
	}
}

// TestVerify tests verifying plaintext password against stored hash
func TestVerify(t *testing.T) {
	// Simulate registration: hash a password
	hash, _ := Generate("mysecretpassword")

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
	hash, _ := Generate("mysecretpassword")
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
	hash, _ := Generate("testpassword")
	pw := Password(hash)

	// Empty plaintext password - should still go through verification to prevent timing attacks
	valid, err := pw.Verify("")
	if err != nil {
		t.Errorf("Verify() returned error for empty plaintext: %v", err)
	}
	if valid {
		t.Error("Verify() should return false for empty plaintext")
	}

	// Empty hash
	pw2 := Password("")
	valid, err = pw2.Verify("password")
	if err == ErrInvalidHash {
		// Expected - empty hash should fail during parsing
	} else if err != nil {
		t.Errorf("Verify() returned unexpected error: %v", err)
	}
	if valid {
		t.Error("Verify() should return false for empty hash")
	}

	// Both empty
	pw3 := Password("")
	valid, err = pw3.Verify("")
	if err == ErrInvalidHash {
		// Expected
	} else if err != nil {
		t.Errorf("Verify() returned unexpected error: %v", err)
	}
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

func TestVerifyDuplicateParameters(t *testing.T) {
	// Hash with duplicate memory parameter
	hash := "$argon2id$v=19$m=65536,m=131072,t=1,p=4$Lr27TtuSl/CAmXzbPLageA$bNemdbSgi3MtyvlnVoU1xnQ4eICpp4ObVprA1gbNDRU"
	pw := Password(hash)
	_, err := pw.Verify("test")
	if err == nil {
		t.Error("Should reject duplicate parameters")
	}
}

func TestVerifyMissingParameters(t *testing.T) {
	// Missing memory parameter
	hash := "$argon2id$v=19$t=1,p=4$Lr27TtuSl/CAmXzbPLageA$bNemdbSgi3MtyvlnVoU1xnQ4eICpp4ObVprA1gbNDRU"
	pw := Password(hash)
	_, err := pw.Verify("test")
	if err == nil {
		t.Error("Should reject missing parameters")
	}
}

func TestVerifyZeroParameters(t *testing.T) {
	// Zero memory parameter
	hash := "$argon2id$v=19$m=0,t=1,p=4$Lr27TtuSl/CAmXzbPLageA$bNemdbSgi3MtyvlnVoU1xnQ4eICpp4ObVprA1gbNDRU"
	pw := Password(hash)
	_, err := pw.Verify("test")
	if err == nil {
		t.Error("Should reject zero parameters")
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
		hash, err := Generate(plaintext)
		if err != nil {
			t.Errorf("Generate() error for password %q: %v", plaintext, err)
			continue
		}

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
