# Jetta

[![CI](https://github.com/Sam-Lane/jetta/actions/workflows/ci.yml/badge.svg)](https://github.com/Sam-Lane/jetta/actions/workflows/ci.yml)
[![Release](https://github.com/Sam-Lane/jetta/actions/workflows/release.yml/badge.svg)](https://github.com/Sam-Lane/jetta/actions/workflows/release.yml)

A fast, secure JWT (JSON Web Token) CLI tool for decoding and validating tokens. Think jwt.io but for your command line.

## Features

- **Decode JWTs** without requiring secrets - inspect headers and payloads instantly
- **Validate signatures** with cryptographic verification
- **Encode new JWTs** with automatic algorithm detection and smart defaults
- **All major algorithms supported**: HMAC (HS256/384/512), RSA (RS256/384/512, PS256/384/512), ECDSA (ES256/384), EdDSA
- **Multiple input methods**: CLI argument, file, or stdin
- **Multiple output formats**: Human-readable (colorful), structured table, or JSON
- **Multiple key sources**: Direct input, file, or environment variable

## Installation

### Homebrew (macOS and Linux)

The easiest way to install Jetta on macOS or Linux is via Homebrew:

```bash
# Add the tap
brew tap sam-lane/tap

# Install Jetta
brew install jetta

# Upgrade to the latest version
brew upgrade jetta
```

### Pre-built Binaries

Download the latest release for your platform from the [releases page](https://github.com/Sam-Lane/jetta/releases).

Available platforms:
- Linux (x86_64, ARM64)
- macOS (Intel, Apple Silicon)
- Windows (x86_64)

**Note**: Starting with v1.0.0, binary artifacts follow the naming convention:
- `jetta_{version}_{os}_{arch}.tar.gz` (e.g., `jetta_1.0.0_linux_amd64.tar.gz`)
- `jetta_{version}_{os}_{arch}.zip` for Windows

```bash
# Example: Install on Linux/macOS (v1.0.0+)
curl -LO https://github.com/Sam-Lane/jetta/releases/latest/download/jetta_1.0.0_linux_amd64.tar.gz
tar -xzf jetta_1.0.0_linux_amd64.tar.gz
sudo mv jetta /usr/local/bin/
```

Each release includes SHA256 checksums for verification.

### From Source

```bash
git clone https://github.com/Sam-Lane/jetta.git
cd jetta
cargo install --path .
```

### From Crates.io (coming soon)

```bash
cargo install jetta
```

## Quick Start

### Interactive Mode (New!)

Run `jetta` without any arguments to enter interactive mode with a cool animation:

```bash
jetta
```

This will:
1. Show an animated transformation from base64 JWT → random characters → JSON
2. Prompt you to paste a JWT token
3. Decode the token and display the results

Skip the animation with `--no-animation`:

```bash
jetta --no-animation
```

### Decode a JWT

```bash
# Decode from command line argument
jetta decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Decode from file
jetta decode --file token.txt

# Decode from stdin (use '-' for explicit stdin)
cat token.txt | jetta decode -
echo $TOKEN | jetta decode -

# JSON output for scripting
jetta decode --format json $TOKEN | jq '.payload.sub'
```

### Validate a JWT Signature

```bash
# Validate with HMAC secret
jetta validate --secret "your-secret-key" $TOKEN

# Validate with secret from file
jetta validate --secret-file secret.txt $TOKEN

# Validate with RSA/ECDSA/EdDSA public key
jetta validate --public-key public-key.pem $TOKEN

# Use environment variable
export JETTA_SECRET="your-secret-key"
jetta validate $TOKEN
```

### Encode a New JWT

```bash
# Create a token with HMAC secret (algorithm auto-detected as HS256)
jetta encode --payload-file claims.json --secret "your-secret-key"

# Create with RSA private key (algorithm auto-detected as RS256)
jetta encode --payload-file claims.json --private-key private.pem

# Override algorithm explicitly
jetta encode --payload-file claims.json --secret "key" --algorithm HS512

# Use custom header
jetta encode --payload-file claims.json --header-file header.json --secret "key"

# JSON output with metadata
jetta encode --payload-file claims.json --secret "key" --format json
```

## Usage

### Interactive Mode

Simply run `jetta` with no commands to enter interactive mode:

```bash
# With animation
jetta

# Skip animation
jetta --no-animation

# Pipe from stdin (skips prompt)
echo $TOKEN | jetta --no-animation
```

The animation morphs from base64 JWT through colorful random characters to a compact JSON representation of the decoded token.

### Commands

#### `decode` - Decode without validation

Decode a JWT token without validating the signature. Useful for inspecting token contents.

```bash
jetta decode <TOKEN> [OPTIONS]
```

**Arguments:**
- `<TOKEN>` - JWT token string (required, use `-` to read from stdin)

**Options:**
- `-f, --file <FILE>` - Read token from file (takes precedence over TOKEN argument)
- `-o, --format <FORMAT>` - Output format: `human` (default), `table`, or `json`

**Examples:**
```bash
# Basic decode with colorful output
jetta decode $TOKEN

# Decode with JSON output
jetta decode --format json $TOKEN

# Decode from file
jetta decode --file my-token.txt

# Decode from stdin
echo $TOKEN | jetta decode -
cat my-token.txt | jetta decode -
```

#### `validate` - Validate signature

Validate a JWT signature and decode it. Exits with code 1 if validation fails.

```bash
jetta validate <TOKEN> [OPTIONS]
```

**Arguments:**
- `<TOKEN>` - JWT token string (required, use `-` to read from stdin)

**Options:**
- `-s, --secret <SECRET>` - Secret key for HMAC algorithms
- `--secret-file <FILE>` - Read secret from file
- `-k, --public-key <FILE>` - Public key file in PEM format (for RSA/ECDSA/EdDSA)
- `-o, --format <FORMAT>` - Output format: `human` (default), `table`, or `json`
- `-f, --file <FILE>` - Read token from file (takes precedence over TOKEN argument)

**Examples:**
```bash
# Validate with HMAC secret
jetta validate --secret "my-secret" $TOKEN

# Validate with RSA public key
jetta validate --public-key rsa-public.pem $TOKEN

# Use environment variable
export JETTA_SECRET="my-secret"
jetta validate $TOKEN

# JSON output
jetta validate --secret "my-secret" --format json $TOKEN

# Validate from stdin
echo $TOKEN | jetta validate --secret "my-secret" -
```

#### `encode` - Create and sign a new JWT

Encode and sign a new JWT token with automatic algorithm detection and smart defaults.

```bash
jetta encode --payload-file <FILE> [OPTIONS]
```

**Options:**
- `-p, --payload-file <FILE>` - Payload JSON file (required)
- `--header-file <FILE>` - Custom header JSON file (optional, smart defaults generated)
- `-s, --secret <SECRET>` - Secret key for HMAC algorithms
- `--secret-file <FILE>` - Read secret from file
- `-k, --private-key <FILE>` - Private key file in PEM format (for RSA/ECDSA/EdDSA)
- `-a, --algorithm <ALG>` - Explicitly specify signing algorithm (auto-detected if not provided)
- `-o, --format <FORMAT>` - Output format: `human` (raw token, default) or `json` (with metadata)

**Algorithm Auto-Detection:**
- HMAC secret → defaults to HS256
- RSA private key → defaults to RS256
- EC private key → defaults to ES256
- EdDSA key → defaults to EdDSA
- Use `--algorithm` to override (e.g., HS512, RS384, ES384)

**Header Generation:**
- If `--header-file` not provided: generates `{"alg": "<detected>", "typ": "JWT"}`
- If `--header-file` provided: uses custom header but always overrides `alg` for safety
- Standard JWT header fields supported: `typ`, `kid`, `cty`, `jku`, `x5u`

**Examples:**
```bash
# Create payload file
echo '{"sub": "user123", "name": "Alice", "admin": true}' > payload.json

# Basic encoding with HMAC (HS256 auto-detected)
jetta encode --payload-file payload.json --secret "my-secret-key"
# Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Use HS512 explicitly
jetta encode --payload-file payload.json --secret "key" --algorithm HS512

# Encode with RSA private key (RS256 auto-detected)
jetta encode --payload-file payload.json --private-key rsa-private.pem

# Use secret from file
jetta encode --payload-file payload.json --secret-file secret.txt

# Custom header with key ID
echo '{"typ": "JWT", "kid": "key-2024-01"}' > header.json
jetta encode --payload-file payload.json --header-file header.json --secret "key"

# JSON output with metadata
jetta encode --payload-file payload.json --secret "key" --format json
# Output:
# {
#   "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
#   "header": {"alg": "HS256", "typ": "JWT"},
#   "payload": {"sub": "user123", "name": "Alice", "admin": true},
#   "algorithm": "HS256"
# }

# Use environment variable
export JETTA_SECRET="my-secret"
jetta encode --payload-file payload.json

# Round-trip: encode then validate
TOKEN=$(jetta encode --payload-file payload.json --secret "key")
jetta validate --secret "key" $TOKEN
```

## Algorithm Support

| Algorithm | Type | Validation Key | Encoding Key |
|-----------|------|----------------|--------------|
| HS256 | HMAC | String or file | String or file |
| HS384 | HMAC | String or file | String or file |
| HS512 | HMAC | String or file | String or file |
| RS256 | RSA | PEM public key | PEM private key |
| RS384 | RSA | PEM public key | PEM private key |
| RS512 | RSA | PEM public key | PEM private key |
| PS256 | RSA-PSS | PEM public key | PEM private key |
| PS384 | RSA-PSS | PEM public key | PEM private key |
| PS512 | RSA-PSS | PEM public key | PEM private key |
| ES256 | ECDSA | PEM public key (PKCS8) | PEM private key |
| ES384 | ECDSA | PEM public key (PKCS8) | PEM private key |
| EdDSA | EdDSA | PEM public key | PEM private key |

### Key Format Notes

- **HMAC (HS*)**: Use raw secret string or text file (for both validation and encoding)
- **RSA (RS*, PS*)**: 
  - Validation: PEM-encoded RSA public key
  - Encoding: PEM-encoded RSA private key
- **ECDSA (ES*)**: 
  - Validation: PEM-encoded EC public key in PKCS8 format
  - Encoding: PEM-encoded EC private key
  - To convert SEC1 to PKCS8: `openssl pkeyutl -pubin -in ec-sec1.pem -out ec-pkcs8.pem`
- **EdDSA**: 
  - Validation: PEM-encoded EdDSA public key
  - Encoding: PEM-encoded EdDSA private key

### Algorithm Auto-Detection (Encode)

When using `encode` without `--algorithm`, Jetta automatically detects the appropriate algorithm:

| Key Type | Default Algorithm | Override Options |
|----------|------------------|------------------|
| HMAC secret (`--secret`) | HS256 | HS384, HS512 |
| RSA private key | RS256 | RS384, RS512, PS256, PS384, PS512 |
| EC private key | ES256 | ES384 |
| EdDSA key | EdDSA | (none) |

## Output Formats

### Human-Readable (Default)

Colorful, formatted output perfect for interactive use:

```
=== JWT Header ===
  Algorithm: HS256
  Type: JWT

=== JWT Payload ===
  Subject: 1234567890
  Issued At: 1516239022 (2018-01-18 01:30:22 UTC)

  Custom Claims:
    name: John Doe

=== Token Analysis ===
  Algorithm: HS256
  Has Signature: YES
```

### Table

Structured table format with Unicode box-drawing characters:

```
┌───────────┬──────────────────────────────────────────────┐
│           Header                                          │
├───────────┼──────────────────────────────────────────────┤
│ alg       │ HS256                                        │
│ typ       │ JWT                                          │
├───────────┼──────────────────────────────────────────────┤
│           Payload                                         │
├───────────┼──────────────────────────────────────────────┤
│ sub       │ 1234567890                                   │
│ name      │ John Doe                                     │
│ iat       │ 1516239022 (2018-01-18 01:30:22 UTC)        │
├───────────┼──────────────────────────────────────────────┤
│           Signature                                       │
├───────────┼──────────────────────────────────────────────┤
│ value     │ SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  │
├───────────┼──────────────────────────────────────────────┤
│           Validation                                      │
├───────────┼──────────────────────────────────────────────┤
│ status    │ VALID                                        │
│ algorithm │ HS256                                        │
└───────────┴──────────────────────────────────────────────┘
```

Features:
- Section headers (Header, Payload, Signature, Validation) centered and spanning both columns
- Timestamps shown in both Unix and human-readable formats
- Complex values (arrays, objects) displayed as compact JSON
- Long values automatically truncated to 100 characters with `...` ellipsis

### JSON

Machine-readable output for scripting and automation:

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022
  },
  "analysis": {
    "algorithm": "HS256",
    "has_signature": true,
    "issued_at": 1516239022
  }
}
```

## Environment Variables

- `JETTA_SECRET` - Default secret for HMAC validation (fallback if no --secret provided)

## Examples

### Create and use test tokens

```bash
# Create a test token
echo '{"sub": "testuser", "exp": 1735689600}' > test-payload.json
TOKEN=$(jetta encode --payload-file test-payload.json --secret "test-secret")

# Decode it
jetta decode $TOKEN

# Validate it
jetta validate --secret "test-secret" $TOKEN
```

### Automation workflow - generate tokens for testing

```bash
#!/bin/bash
# generate-test-tokens.sh

# Create different test scenarios
echo '{"sub": "admin", "role": "admin"}' > admin.json
echo '{"sub": "user", "role": "user"}' > user.json
echo '{"sub": "guest"}' > guest.json

# Generate tokens
ADMIN_TOKEN=$(jetta encode --payload-file admin.json --secret "$SECRET")
USER_TOKEN=$(jetta encode --payload-file user.json --secret "$SECRET")
GUEST_TOKEN=$(jetta encode --payload-file guest.json --secret "$SECRET")

# Use them in API tests
curl -H "Authorization: Bearer $ADMIN_TOKEN" https://api.example.com/admin
curl -H "Authorization: Bearer $USER_TOKEN" https://api.example.com/user
curl -H "Authorization: Bearer $GUEST_TOKEN" https://api.example.com/guest
```

### Decode with different formats

```bash
# Human-readable (default, colorful)
jetta decode $TOKEN

# Structured table
jetta decode --format table $TOKEN

# JSON for scripting
jetta decode --format json $TOKEN | jq -r '.payload.email'
```

### Validate and check expiration

```bash
if jetta validate --secret "$SECRET" $TOKEN; then
    echo "Token is valid!"
else
    echo "Token validation failed!"
fi
```

### Batch processing tokens from file

```bash
while read -r token; do
    echo "Processing token..."
    jetta decode "$token"
done < tokens.txt
```

## Common Errors

### "required arguments were not provided: <TOKEN>"

This error occurs when you run `jetta decode` or `jetta validate` without providing a token.

**Solutions:**
- Provide a token as an argument: `jetta decode <your-token>`
- Use `-` to read from stdin: `echo $TOKEN | jetta decode -`
- Use `--file` to read from a file: `jetta decode --file token.txt`
- For interactive use, just run `jetta` without any command

### "No token provided from stdin"

This occurs when using `-` for stdin but no input is provided.

**Solutions:**
- Ensure you're piping data: `echo $TOKEN | jetta decode -`
- Or use a file instead: `jetta decode --file token.txt`

### "Malformed JWT"

The provided token is not a valid JWT format (must be three base64 parts separated by dots).

**Solutions:**
- Verify the token is complete and properly copied
- Check for extra whitespace or newlines
- Ensure it follows the format: `header.payload.signature`

### Create a token checker script

```bash
#!/bin/bash
# check-token.sh
export JETTA_SECRET="$(cat .secret)"
jetta validate --format json "$1" | jq '{
    valid: .valid,
    subject: .token.payload.sub,
    expires: .token.analysis.expires_at
}'
```

## Building from Source

### Requirements

- Rust 1.88.0 or later
- Cargo

### Build

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Run integration tests
cargo test --test integration_tests
```

## Development

### Project Structure

```
src/
├── main.rs       # CLI entry point and argument parsing
├── decode.rs     # JWT decoding logic
├── validate.rs   # Signature validation
├── encode.rs     # JWT encoding and signing
├── output.rs     # Output formatting (human/JSON/table)
├── animation.rs  # Welcome animation logic
└── types.rs      # Shared data structures
```

### Running Tests

```bash
# All tests
cargo test

# Unit tests only
cargo test --lib

# Integration tests only
cargo test --test integration_tests

# Specific test
cargo test test_decode_valid_token
```

## License

MIT License - see LICENSE file for details

## Contributing

Contributions welcome! Please open an issue or PR.

### Release Process

Releases are automated via GitHub Actions and GoReleaser:

1. Update `CHANGELOG.md` with changes for the new version
2. Update version in `Cargo.toml`
3. Run quality checks: `cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings && cargo test`
4. Commit changes: `git commit -am "chore: release v1.0.0"`
5. Create and push a tag: `git tag v1.0.0 && git push origin v1.0.0`
6. GitHub Actions will automatically:
   - Build binaries for all platforms using GoReleaser
   - Generate SHA256 checksums
   - Create a GitHub release with assets
   - Extract release notes from CHANGELOG.md
   - Update the Homebrew tap with the new cask version

### CI/CD

This project uses GitHub Actions for continuous integration and releases:

- **CI Workflow** (`ci.yml`): Runs on every push and PR
  - Tests on Linux, macOS, and Windows
  - Checks code formatting with rustfmt
  - Lints code with clippy (warnings treated as errors with `-D warnings`)
  
- **Release Workflow** (`release.yml`): Runs on version tags
  - Uses GoReleaser with native Rust builder
  - Builds optimized binaries for 5 platforms via cargo-zigbuild
  - Generates checksums for verification
  - Creates GitHub releases automatically
  - Updates Homebrew tap (sam-lane/tap) with new cask
