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
	ErrInvalidHash   = errors.New("invalid hash format")
	ErrIncompatible  = errors.New("incompatible version of argon2")
)

// Generate returns a hashed version of the given password using Argon2id.
// The returned string contains the encoded parameters, salt, and hash.
func Generate(pw string) string {
	if pw == "" {
		return ""
	}

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

// Verify checks if the given password matches the hash.
// It returns true if they match, false otherwise.
// An error is returned if the hash format is invalid.
func Verify(pw, encodedHash string) (bool, error) {
	if pw == "" || encodedHash == "" {
		return false, nil
	}

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
