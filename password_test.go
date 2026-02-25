package password

import (
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
}

func TestGenerate_Empty(t *testing.T) {
	hash := Generate("")
	if hash != "" {
		t.Error("Generate() should handle empty passwords")
	}
}
