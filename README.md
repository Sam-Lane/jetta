# Jetta

[![CI](https://github.com/Sam-Lane/jetta/actions/workflows/ci.yml/badge.svg)](https://github.com/Sam-Lane/jetta/actions/workflows/ci.yml)
[![Release](https://github.com/Sam-Lane/jetta/actions/workflows/release.yml/badge.svg)](https://github.com/Sam-Lane/jetta/actions/workflows/release.yml)

A fast, secure JWT (JSON Web Token) CLI tool for decoding and validating tokens. Think jwt.io but for your command line.

## Features

- **Decode JWTs** without requiring secrets - inspect headers and payloads instantly
- **Validate signatures** with cryptographic verification
- **All major algorithms supported**: HMAC (HS256/384/512), RSA (RS256/384/512, PS256/384/512), ECDSA (ES256/384), EdDSA
- **Multiple input methods**: CLI argument, file, or stdin
- **Multiple output formats**: Human-readable (colorful) or JSON
- **Multiple key sources**: Direct input, file, or environment variable

## Installation

### Pre-built Binaries (Recommended)

Download the latest release for your platform from the [releases page](https://github.com/Sam-Lane/jetta/releases).

Available platforms:
- Linux (x86_64, ARM64)
- macOS (Intel, Apple Silicon)
- Windows (x86_64)

```bash
# Example: Install on Linux/macOS
curl -LO https://github.com/Sam-Lane/jetta/releases/latest/download/jetta-x86_64-unknown-linux-gnu.tar.gz
tar -xzf jetta-x86_64-unknown-linux-gnu.tar.gz
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

# Decode from stdin
cat token.txt | jetta decode
echo $TOKEN | jetta decode

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
jetta decode [OPTIONS] [TOKEN]
```

**Options:**
- `-f, --file <FILE>` - Read token from file
- `-o, --format <FORMAT>` - Output format: `human` (default) or `json`

**Examples:**
```bash
# Basic decode with colorful output
jetta decode $TOKEN

# Decode with JSON output
jetta decode --format json $TOKEN

# Decode from file
jetta decode --file my-token.txt
```

#### `validate` - Validate signature

Validate a JWT signature and decode it. Exits with code 1 if validation fails.

```bash
jetta validate [OPTIONS] [TOKEN]
```

**Options:**
- `-s, --secret <SECRET>` - Secret key for HMAC algorithms
- `--secret-file <FILE>` - Read secret from file
- `-k, --public-key <FILE>` - Public key file in PEM format (for RSA/ECDSA/EdDSA)
- `-o, --format <FORMAT>` - Output format: `human` (default) or `json`

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
```

## Algorithm Support

| Algorithm | Type | Secret/Key Format |
|-----------|------|-------------------|
| HS256 | HMAC | String or file |
| HS384 | HMAC | String or file |
| HS512 | HMAC | String or file |
| RS256 | RSA | PEM public key |
| RS384 | RSA | PEM public key |
| RS512 | RSA | PEM public key |
| PS256 | RSA-PSS | PEM public key |
| PS384 | RSA-PSS | PEM public key |
| PS512 | RSA-PSS | PEM public key |
| ES256 | ECDSA | PEM public key (PKCS8) |
| ES384 | ECDSA | PEM public key (PKCS8) |
| EdDSA | EdDSA | PEM public key |

### Key Format Notes

- **HMAC (HS*)**: Use raw secret string or text file
- **RSA (RS*, PS*)**: Use PEM-encoded RSA public key
- **ECDSA (ES*)**: Use PEM-encoded EC public key in PKCS8 format
  - To convert SEC1 to PKCS8: `openssl pkeyutl -pubin -in ec-sec1.pem -out ec-pkcs8.pem`
- **EdDSA**: Use PEM-encoded EdDSA public key

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

### Decode and extract specific claim

```bash
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
├── output.rs     # Output formatting (human/JSON)
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

Releases are automated via GitHub Actions:

1. Update `CHANGELOG.md` with changes for the new version
2. Update version in `Cargo.toml`
3. Commit changes: `git commit -am "Release v0.2.0"`
4. Create and push a tag: `git tag v0.2.0 && git push origin v0.2.0`
5. GitHub Actions will automatically:
   - Build binaries for all platforms
   - Generate SHA256 checksums
   - Create a GitHub release with assets
   - Extract release notes from CHANGELOG.md

### CI/CD

This project uses GitHub Actions for continuous integration and releases:

- **CI Workflow** (`ci.yml`): Runs on every push and PR
  - Tests on Linux, macOS, and Windows
  - Checks code formatting with rustfmt
  - Lints code with clippy
  
- **Release Workflow** (`release.yml`): Runs on version tags
  - Builds optimized binaries for 5 platforms
  - Generates checksums for verification
  - Creates GitHub releases automatically

## Security

If you discover a security vulnerability, please email security@example.com instead of using the issue tracker.
