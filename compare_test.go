package password

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"golang.org/x/crypto/argon2"
)

type PasswordString string
type PasswordBytes []byte

func (p PasswordString) HashString() string {
	if p == "" { return "" }
	salt := make([]byte, 16)
	rand.Read(salt)
	hash := argon2.IDKey([]byte(p), salt, 1, 64*1024, 4, 32)  // need []byte(p)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", 64*1024, 1, 4, b64Salt, b64Hash)
}

func (p PasswordBytes) HashBytes() string {
	if len(p) == 0 { return "" }
	salt := make([]byte, 16)
	rand.Read(salt)
	hash := argon2.IDKey(p, salt, 1, 64*1024, 4, 32)  // no conversion needed
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", 64*1024, 1, 4, b64Salt, b64Hash)
}

func BenchmarkHashStringVersion(b *testing.B) {
	pw := PasswordString("testpassword123")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pw.HashString()
	}
}

func BenchmarkHashBytesVersion(b *testing.B) {
	pw := PasswordBytes([]byte("testpassword123"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pw.HashBytes()
	}
}
