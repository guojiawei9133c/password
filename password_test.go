package password

import (
	"testing"
)

// TestPasswordType tests the Password type and its methods
func TestPasswordType_New(t *testing.T) {
	pw := New("testpassword")
	if pw == nil {
		t.Fatal("New() returned nil")
	}
	if pw.String() != "testpassword" {
		t.Errorf("String() = %q, want %q", pw.String(), "testpassword")
	}
}

func TestPasswordType_NewEmpty(t *testing.T) {
	pw := New("")
	if pw == nil {
		t.Fatal("New() returned nil for empty password")
	}
	if pw.String() != "" {
		t.Errorf("String() = %q, want empty", pw.String())
	}
}

func TestPasswordType_Hash(t *testing.T) {
	pw := New("testpassword")
	hash := pw.Hash()

	if hash == "" {
		t.Error("Hash() returned empty string")
	}

	// Hash should not be the same as the original password
	if hash == pw.String() {
		t.Error("Hash() returned the original password")
	}

	// Multiple calls should produce different hashes (due to random salt)
	hash2 := pw.Hash()
	if hash == hash2 {
		t.Error("Hash() should produce different results on each call")
	}
}

func TestPasswordType_HashEmpty(t *testing.T) {
	pw := New("")
	hash := pw.Hash()
	if hash != "" {
		t.Error("Hash() should return empty string for empty password")
	}
}

func TestPasswordType_Verify(t *testing.T) {
	pw := New("mysecretpassword")
	hash := pw.Hash()

	valid, err := pw.Verify(hash)
	if err != nil {
		t.Errorf("Verify() returned error: %v", err)
	}
	if !valid {
		t.Error("Verify() failed to validate correct password")
	}
}

func TestPasswordType_VerifyWrongPassword(t *testing.T) {
	pw1 := New("mysecretpassword")
	hash := pw1.Hash()

	pw2 := New("wrongpassword")
	valid, err := pw2.Verify(hash)
	if err != nil {
		t.Errorf("Verify() returned error: %v", err)
	}
	if valid {
		t.Error("Verify() incorrectly validated wrong password")
	}
}

func TestPasswordType_VerifyEmptyInputs(t *testing.T) {
	pw := New("testpassword")
	hash := pw.Hash()

	// Empty password
	pw2 := New("")
	valid, _ := pw2.Verify(hash)
	if valid {
		t.Error("Verify() should return false for empty password")
	}

	// Empty hash
	valid, _ = pw.Verify("")
	if valid {
		t.Error("Verify() should return false for empty hash")
	}
}

func TestPasswordType_VerifyInvalidHash(t *testing.T) {
	pw := New("password")
	invalidHashes := []string{
		"not_a_hash",
		"$argon2id",
		"$argon2id$v=19$m=notanumber",
	}

	for _, h := range invalidHashes {
		_, err := pw.Verify(h)
		if err == nil {
			t.Errorf("Verify() should return error for invalid hash: %s", h)
		}
	}
}

func TestPasswordType_Roundtrip(t *testing.T) {
	passwords := []string{
		"simple",
		"complex!@#$%^&*()_+",
		"unicode世界",
		"a" + "verylong" + "verylong" + "verylong" + "verylong" + "verylong",
	}

	for _, pwStr := range passwords {
		pw := New(pwStr)
		hash := pw.Hash()

		valid, err := pw.Verify(hash)
		if err != nil {
			t.Errorf("Verify() error for password %q: %v", pwStr, err)
		}
		if !valid {
			t.Errorf("Verify() failed for password %q", pwStr)
		}

		// Verify wrong password doesn't match
		pwWrong := New(pwStr + "x")
		valid, _ = pwWrong.Verify(hash)
		if valid {
			t.Errorf("Verify() incorrectly validated modified password for %q", pwStr)
		}
	}
}

func TestPasswordType_String(t *testing.T) {
	pw := New("secret")
	if pw.String() != "secret" {
		t.Errorf("String() = %q, want %q", pw.String(), "secret")
	}
}

// TestGenerate_Function tests the legacy Generate function for backward compatibility
func TestGenerate_Function(t *testing.T) {
	pw := "testpassword123"
	hash := Generate(pw)

	if hash == "" {
		t.Error("Generate() returned empty string")
	}

	if hash == pw {
		t.Error("Generate() returned the original password instead of a hash")
	}

	hash2 := Generate(pw)
	if hash == hash2 {
		t.Error("Generate() should produce different hashes for the same password")
	}
}

func TestVerify_Function(t *testing.T) {
	pw := "mysecretpassword"
	hash := Generate(pw)

	valid, err := Verify(pw, hash)
	if err != nil {
		t.Errorf("Verify() returned error: %v", err)
	}
	if !valid {
		t.Error("Verify() failed to validate correct password")
	}

	valid, _ = Verify("wrongpassword", hash)
	if valid {
		t.Error("Verify() incorrectly validated wrong password")
	}
}
