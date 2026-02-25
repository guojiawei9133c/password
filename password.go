// Package password provides Argon2id password hashing functionality.
//
// The package uses Argon2id (RFC 9106) with secure defaults for password hashing
// and verification. It follows the PHC (Password Hashing Competition) string format.
//
// Security features:
//   - Argon2id algorithm (recommended for password hashing)
//   - Constant-time comparison to prevent timing attacks
//   - Random salt generation using crypto/rand
//
// Default parameters:
//   - Memory: 64 MiB (m=65536 in KiB)
//   - Time cost: 1 pass
//   - Parallelism: 4 threads
//   - Salt length: 16 bytes
//   - Key length: 32 bytes
//
// Example:
//
//	// Generate hash during registration
//	hash, err := password.Generate("user_password")
//	if err != nil {
//	    // Handle error
//	}
//	// Store hash in database
//
//	// Verify password during login
//	pw := password.Password(storedHash)
//	valid, err := pw.Verify(userInput)
//	if err != nil {
//	    // Handle invalid hash format
//	}
//	if valid {
//	    // Password is correct
//	}
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
	// ErrInvalidHash is returned when the stored hash format is invalid.
	ErrInvalidHash = errors.New("invalid hash format")

	// ErrIncompatible is returned when the Argon2 version is not supported.
	ErrIncompatible = errors.New("incompatible version of argon2")

	// ErrPasswordMismatch is returned when the password does not match the stored hash.
	ErrPasswordMismatch = errors.New("password mismatch")

	// ErrEmptyPassword is returned when attempting to generate a hash from an empty password.
	ErrEmptyPassword = errors.New("empty password")

	// ErrInvalidParams is returned when hash parameters are invalid (zero, duplicate, etc.).
	ErrInvalidParams = errors.New("invalid parameters")
)

// Password represents a stored password hash that can be verified against plaintext input.
//
// It wraps a PHC-formatted hash string and provides a Verify method
// for password validation.
type Password string

// Verify checks if the plaintext password matches the stored hash.
//
// The method uses constant-time comparison to prevent timing attacks. Even for
// empty inputs, the full verification path is executed to maintain consistent timing.
//
// Parameters:
//   plaintext - the plaintext password to verify
//
// Returns:
//   bool - true if the password matches, false otherwise
//   error - ErrInvalidHash, ErrIncompatible, ErrInvalidParams, or ErrPasswordMismatch
func (p Password) Verify(plaintext string) (bool, error) {
	// Always parse the hash first to prevent timing attacks on empty/invalid hashes
	params, salt, hash, err := parseHash(string(p))
	if err != nil {
		return false, err
	}

	// Always derive hash, even for empty plaintext, to maintain constant-time behavior
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
//
// The returned hash follows the PHC (Password Hashing Competition) format and
// includes all necessary parameters, salt, and the derived hash. This hash
// should be stored securely and later used with Password.Verify() for validation.
//
// Parameters:
//   plaintext - the plaintext password to hash
//
// Returns:
//   string - the PHC-formatted hash string
//   error - ErrEmptyPassword if the password is empty
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

// parseHash parses a PHC-formatted Argon2id hash string.
//
// It validates the format, extracts parameters, salt, and hash, and performs
// sanity checks on the extracted values.
//
// Parameters:
//   encodedHash - the PHC-formatted hash string
//
// Returns:
//   *parameters - the extracted hash parameters
//   []byte - the decoded salt
//   []byte - the decoded hash
//   error - ErrInvalidHash, ErrIncompatible, ErrInvalidParams, or base64 decoding errors
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
