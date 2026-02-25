# password

A Go package for secure password hashing using Argon2id.

## Features

- **Argon2id** algorithm (RFC 9106, PHC format)
- Secure defaults: 64 MiB memory, 1 pass, 4 threads
- Constant-time comparison to prevent timing attacks
- Order-independent parameter parsing
- Full error handling with clear error types

## Installation

```bash
go get github.com/guojiawei9133c/password
```

## Usage

### Generate Password Hash (Registration)

```go
import "github.com/guojiawei9133c/password"

// Generate a hash from plaintext password
hash, err := password.Generate("user_password")
if err != nil {
    // Handle error (e.g., empty password)
}

// Store 'hash' in your database
// Example output: $argon2id$v=19$m=65536,t=1,p=4$Lr27TtuSl/CAmXzbPLageA$bNemdbSgi3MtyvlnVoU1xnQ4eICpp4ObVprA1gbNDRU
```

### Verify Password (Login)

```go
import "github.com/guojiawei9133c/password"

// Retrieve stored hash from database
storedHash := "$argon2id$v=19$m=65536,t=1,p=4$Lr27TtuSl/CAmXzbPLageA$bNemdbSgi3MtyvlnVoU1xnQ4eICpp4ObVprA1gbNDRU"

// Create Password object
pw := password.Password(storedHash)

// Verify against user input
valid, err := pw.Verify("user_input")
if err != nil {
    // Handle invalid hash format
}

if valid {
    // Password is correct
} else {
    // Password is incorrect
}
```

### Error Handling

```go
hash, err := password.Generate("password")
switch err {
case password.ErrEmptyPassword:
    // User submitted empty password
case nil:
    // Success
default:
    // Unexpected error
}
```

## API Reference

### `Generate(plaintext string) (string, error)`

Generates an Argon2id hash from the plaintext password.

**Returns:**
- `(string, error)` - The PHC-formatted hash string and an error if any

**Errors:**
- `ErrEmptyPassword` - Password is empty
- Other errors from salt generation or encoding

---

### `Password` Type

Represents a stored password hash.

#### `Verify(plaintext string) (bool, error)`

Verifies if the plaintext password matches the stored hash.

**Returns:**
- `(bool, error)` - `true` if password matches, `false` otherwise
- Error if hash format is invalid

**Errors:**
- `ErrInvalidHash` - Hash format is invalid
- `ErrIncompatible` - Argon2 version is incompatible
- `ErrPasswordMismatch` - Password does not match
- `ErrInvalidParams` - Hash parameters are invalid

---

## Security Considerations

- **Argon2id** is the recommended variant (hybrid of Argon2i and Argon2d)
- Uses constant-time comparison to prevent timing attacks
- Random salt generated with `crypto/rand`
- Always validates full hash even for empty inputs to prevent timing side-channels

## Format Details

The hash string follows PHC (Password Hashing Competition) format:

```
$argon2id$v=19$m=65536,t=1,p=4$<base64_salt>$<base64_hash>
```

| Part | Description |
|-------|-------------|
| `argon2id` | Algorithm type |
| `v=19` | Version |
| `m=65536` | Memory cost (in KiB, ~64 MiB) |
| `t=1` | Time cost (number of passes) |
| `p=4` | Parallelism (number of threads) |
| `<base64_salt>` | Random salt (16 bytes) |
| `<base64_hash>` | Derived hash (32 bytes) |

## Benchmark Results

```
BenchmarkGenerate/Normal-32    100  104499499 ns/op  67120340 B/op  47 allocs/op
BenchmarkVerify/Correct-32     100  142067530 ns/op  67119367 B/op  49 allocs/op
```

Note: The slow performance (~100ms) is expected and necessary for security. Argon2id is memory-hard to resist GPU/ASIC attacks.

## License

[Specify your license here]

## Contributing

Contributions are welcome! Please ensure:
- All tests pass: `go test ./...`
- Code is formatted: `go fmt ./...`
- No new lint issues
