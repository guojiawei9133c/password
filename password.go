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
	ErrInvalidHash     = errors.New("invalid hash format")
	ErrIncompatible    = errors.New("incompatible version of argon2")
	ErrPasswordMismatch = errors.New("password mismatch")
	ErrEmptyPassword  = errors.New("empty password")
	ErrInvalidParams  = errors.New("invalid parameters")
)

// Password represents a stored password hash that can be verified against plaintext input.
type Password string

// Verify checks if the plaintext password matches the stored hash.
// It returns true if they match, false otherwise.
// An error is returned if the stored hash format is invalid.
func (p Password) Verify(plaintext string) (bool, error) {
	// Always parse the hash first to prevent timing attacks on empty/invalid hashes
	params, salt, hash, err := parseHash(string(p))
	if err != nil {
		return false, err
	}

	// Always derive the hash, even for empty plaintext, to maintain constant-time behavior
	derivedHash := argon2.IDKey([]byte(plaintext), salt, params.time, params.memory, params.threads, params.keyLen)

	// Check empty plaintext AFTER deriving to avoid timing leaks
	if plaintext == "" {
		// Still perform constant-time comparison to prevent timing analysis
		subtle.ConstantTimeCompare(derivedHash, hash)
		return false, nil
	}

	// Constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(derivedHash, hash) == 1 {
		return true, nil
	}
	return false, ErrPasswordMismatch
}

// Generate returns an Argon2id hash of the given plaintext password.
// This is typically used during user registration.
// The returned hash should be stored and later used with Password(hash).Verify().
func Generate(plaintext string) (string, error) {
	if plaintext == "" {
		return "", ErrEmptyPassword
	}

	// Generate a random salt
	salt := make([]byte, defaultSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive the key using Argon2id
	hash := argon2.IDKey([]byte(plaintext), salt, defaultTime, defaultMemory, defaultThreads, defaultKeyLength)

	// Format: $argon2id$v=19$<base64 salt>$<base64 hash> (PHC format)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		defaultMemory, defaultTime, defaultThreads, b64Salt, b64Hash), nil
}

type parameters struct {
	memory  uint32
	time    uint32
	threads uint8
	keyLen  uint32
}

func parseHash(encodedHash string) (*parameters, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	// Format: $argon2id$v=19$m=...,t=...,p=...$salt$hash (PHC format)
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, nil, nil, ErrInvalidHash
	}

	if parts[2] != "v=19" {
		return nil, nil, nil, ErrIncompatible
	}

	// Parse parameters manually for better flexibility and readability
	// Format: m=65536,t=1,p=4 (order-independent)
	paramStrs := strings.Split(parts[3], ",")
	var paramsValues parameters

	// Track required parameters to detect missing or duplicates
	hasMemory, hasTime, hasThreads := false, false, false

	for _, param := range paramStrs {
		switch {
		case strings.HasPrefix(param, "m="):
			if hasMemory {
				return nil, nil, nil, ErrInvalidHash // duplicate parameter
			}
			if _, err := fmt.Sscanf(param, "m=%d", &paramsValues.memory); err != nil {
				return nil, nil, nil, fmt.Errorf("failed to parse memory parameter: %w", err)
			}
			if paramsValues.memory == 0 {
				return nil, nil, nil, ErrInvalidParams
			}
			hasMemory = true
		case strings.HasPrefix(param, "t="):
			if hasTime {
				return nil, nil, nil, ErrInvalidHash // duplicate parameter
			}
			if _, err := fmt.Sscanf(param, "t=%d", &paramsValues.time); err != nil {
				return nil, nil, nil, fmt.Errorf("failed to parse time cost parameter: %w", err)
			}
			if paramsValues.time == 0 {
				return nil, nil, nil, ErrInvalidParams
			}
			hasTime = true
		case strings.HasPrefix(param, "p="):
			if hasThreads {
				return nil, nil, nil, ErrInvalidHash // duplicate parameter
			}
			if _, err := fmt.Sscanf(param, "p=%d", &paramsValues.threads); err != nil {
				return nil, nil, nil, fmt.Errorf("failed to parse threads parameter: %w", err)
			}
			if paramsValues.threads == 0 {
				return nil, nil, nil, ErrInvalidParams
			}
			hasThreads = true
		}
	}

	// Check all required parameters were found
	if !hasMemory || !hasTime || !hasThreads {
		return nil, nil, nil, ErrInvalidHash
	}

	b64Salt := parts[4]
	b64Hash := parts[5]

	if b64Salt == "" || b64Hash == "" {
		return nil, nil, nil, ErrInvalidHash
	}

	// Decode base64 salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(b64Salt)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(b64Hash)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode hash: %w", err)
	}

	// Validate hash length
	if len(hash) == 0 || len(hash) > 128 {
		return nil, nil, nil, ErrInvalidHash
	}

	paramsValues.keyLen = uint32(len(hash))

	return &paramsValues, salt, hash, nil
}
