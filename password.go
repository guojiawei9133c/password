package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Default parameters for Argon2id (RFC 9106 Section 7.3 recommendations)
const (
	defaultTime      = 1             // Number of passes
	defaultMemory    = 64 * 1024     // 64 MB in KiB
	defaultThreads   = 4             // Number of parallel threads
	defaultKeyLength = 32            // 32 bytes for key length
	defaultSaltLength = 16           // 16 bytes for salt
)

var (
	ErrInvalidHash  = errors.New("invalid hash format")
	ErrIncompatible = errors.New("incompatible version of argon2")
)

// Password represents a plaintext password that can be hashed and verified.
type Password string

// New creates a new Password from the given string.
func New(pw string) *Password {
	p := Password(pw)
	return &p
}

// String returns the plaintext password.
// Use with caution - this exposes the plaintext password.
func (p *Password) String() string {
	if p == nil {
		return ""
	}
	return string(*p)
}

// Hash returns an Argon2id hashed version of the password.
// Each call produces a different hash due to a random salt.
func (p *Password) Hash() string {
	if p == nil || *p == "" {
		return ""
	}

	pw := string(*p)

	// Generate a random salt
	salt := make([]byte, defaultSaltLength)
	if _, err := rand.Read(salt); err != nil {
		panic(fmt.Sprintf("failed to generate salt: %v", err))
	}

	// Derive the key using Argon2id
	hash := argon2.IDKey([]byte(pw), salt, defaultTime, defaultMemory, defaultThreads, defaultKeyLength)

	// Format: $argon2id$v=19$<base64 salt>$<base64 hash>
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		defaultMemory, defaultTime, defaultThreads, b64Salt, b64Hash)
}

// Verify checks if the password matches the given hash.
// It returns true if they match, false otherwise.
// An error is returned if the hash format is invalid.
func (p *Password) Verify(encodedHash string) (bool, error) {
	if p == nil || *p == "" || encodedHash == "" {
		return false, nil
	}

	pw := string(*p)

	// Parse the hash format
	params, salt, hash, err := parseHash(encodedHash)
	if err != nil {
		return false, err
	}

	// Derive the key using the same parameters
	derivedHash := argon2.IDKey([]byte(pw), salt, params.time, params.memory, params.threads, params.keyLen)

	// Constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(derivedHash, hash) == 1 {
		return true, nil
	}
	return false, nil
}

// Generate returns a hashed version of the given password using Argon2id.
// This is a convenience function equivalent to New(pw).Hash().
// Deprecated: Use New(pw).Hash() for better type safety.
func Generate(pw string) string {
	return New(pw).Hash()
}

// VerifyHash checks if the given password matches the hash.
// This is a convenience function equivalent to New(pw).Verify(hash).
// Deprecated: Use New(pw).Verify(hash) for better type safety.
func Verify(pw, encodedHash string) (bool, error) {
	return New(pw).Verify(encodedHash)
}

type parameters struct {
	memory  uint32
	time    uint32
	threads uint8
	keyLen  uint32
}

func parseHash(encodedHash string) (*parameters, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	// Format: $argon2id$v=19$m=...,t=...,p=...$salt$hash
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, nil, nil, ErrInvalidHash
	}

	if parts[2] != "v=19" {
		return nil, nil, nil, ErrIncompatible
	}

	var params parameters
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.memory, &params.time, &params.threads)
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, err
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, err
	}

	params.keyLen = uint32(len(hash))

	return &params, salt, hash, nil
}
