use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

const SAMPLE_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const SAMPLE_SECRET: &str = "your-256-bit-secret";

#[test]
fn test_decode_command() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("decode")
        .arg(SAMPLE_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains("JWT Header"))
        .stdout(predicate::str::contains("HS256"))
        .stdout(predicate::str::contains("John Doe"));
}

#[test]
fn test_decode_json_output() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("decode")
        .arg("--format")
        .arg("json")
        .arg(SAMPLE_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""algorithm": "HS256""#))
        .stdout(predicate::str::contains(r#""name": "John Doe""#));
}

#[test]
fn test_decode_malformed_token() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("decode")
        .arg("invalid.token")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Malformed JWT"));
}

#[test]
fn test_validate_correct_secret() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("validate")
        .arg("--secret")
        .arg(SAMPLE_SECRET)
        .arg(SAMPLE_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));
}

#[test]
fn test_validate_wrong_secret() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("validate")
        .arg("--secret")
        .arg("wrong-secret")
        .arg(SAMPLE_TOKEN)
        .assert()
        .code(1) // Should exit with error code
        .stdout(predicate::str::contains("INVALID"))
        .stdout(predicate::str::contains("InvalidSignature"));
}

#[test]
fn test_validate_json_output() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("validate")
        .arg("--secret")
        .arg(SAMPLE_SECRET)
        .arg("--format")
        .arg("json")
        .arg(SAMPLE_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""valid": true"#));
}

#[test]
fn test_validate_no_secret_provided() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("validate")
        .arg(SAMPLE_TOKEN)
        .assert()
        .failure()
        .stderr(predicate::str::contains("No secret or key provided"));
}

#[test]
fn test_help_command() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Jetta"))
        .stdout(predicate::str::contains("decode"))
        .stdout(predicate::str::contains("validate"));
}

#[test]
fn test_decode_help() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("decode")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Decode a JWT"))
        .stdout(predicate::str::contains("--file"))
        .stdout(predicate::str::contains("--format"));
}

#[test]
fn test_validate_help() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("validate")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Validate a JWT"))
        .stdout(predicate::str::contains("--secret"))
        .stdout(predicate::str::contains("--public-key"));
}

// Note: Interactive mode tests with stdin are complex with assert_cmd
// Manual testing recommended:
// 1. cargo build --release
// 2. echo "eyJhbGci..." | ./target/release/jetta --no-animation
// 3. ./target/release/jetta (without --no-animation to see animation)

#[test]
fn test_decode_requires_token() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("decode")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "required arguments were not provided",
        ))
        .stderr(predicate::str::contains("<TOKEN>"));
}

#[test]
fn test_validate_requires_token() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("validate")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "required arguments were not provided",
        ))
        .stderr(predicate::str::contains("<TOKEN>"));
}

#[test]
fn test_decode_explicit_stdin() {
    assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("jetta"))
        .arg("decode")
        .arg("-")
        .write_stdin(SAMPLE_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains("JWT Header"))
        .stdout(predicate::str::contains("HS256"))
        .stdout(predicate::str::contains("John Doe"));
}

#[test]
fn test_file_takes_precedence() {
    // Create a temporary file with a token
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(temp_file, "{}", SAMPLE_TOKEN).unwrap();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("decode")
        .arg("ignored-token-argument") // This should be ignored
        .arg("--file")
        .arg(temp_file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("JWT Header"))
        .stdout(predicate::str::contains("HS256"))
        .stdout(predicate::str::contains("John Doe"));
}

#[test]
fn test_decode_table_output() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("decode")
        .arg("--format")
        .arg("table")
        .arg(SAMPLE_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains("Header"))
        .stdout(predicate::str::contains("Payload"))
        .stdout(predicate::str::contains("Signature"))
        .stdout(predicate::str::contains("HS256"))
        .stdout(predicate::str::contains("John Doe"))
        .stdout(predicate::str::contains("┌")) // Unicode box-drawing
        .stdout(predicate::str::contains("│"))
        .stdout(predicate::str::contains("└"));
}

#[test]
fn test_validate_table_output() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("validate")
        .arg("--secret")
        .arg(SAMPLE_SECRET)
        .arg("--format")
        .arg("table")
        .arg(SAMPLE_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains("Validation"))
        .stdout(predicate::str::contains("VALID"))
        .stdout(predicate::str::contains("Header"))
        .stdout(predicate::str::contains("Payload"))
        .stdout(predicate::str::contains("┌"))
        .stdout(predicate::str::contains("│"))
        .stdout(predicate::str::contains("└"));
}

#[test]
fn test_table_format_short_flag() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("decode")
        .arg("-o")
        .arg("table")
        .arg(SAMPLE_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains("Header"))
        .stdout(predicate::str::contains("Payload"))
        .stdout(predicate::str::contains("┌"));
}

// ========== Encode Tests ==========

#[test]
fn test_encode_with_hmac_secret() {
    let mut payload_file = NamedTempFile::new().unwrap();
    writeln!(
        payload_file,
        r#"{{"sub": "1234567890", "name": "Test User", "iat": 1516239022}}"#
    )
    .unwrap();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("encode")
        .arg("--payload-file")
        .arg(payload_file.path())
        .arg("--secret")
        .arg("test-secret-key")
        .assert()
        .success()
        .stdout(
            predicate::str::is_match(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\n$")
                .unwrap(),
        );
}

#[test]
fn test_encode_json_output() {
    let mut payload_file = NamedTempFile::new().unwrap();
    writeln!(payload_file, r#"{{"sub": "test-user"}}"#).unwrap();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("encode")
        .arg("--payload-file")
        .arg(payload_file.path())
        .arg("--secret")
        .arg("secret")
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""token":"#))
        .stdout(predicate::str::contains(r#""algorithm":"#))
        .stdout(predicate::str::contains(r#""header":"#))
        .stdout(predicate::str::contains(r#""payload":"#));
}

#[test]
fn test_encode_with_custom_header() {
    let mut payload_file = NamedTempFile::new().unwrap();
    writeln!(payload_file, r#"{{"sub": "test"}}"#).unwrap();

    let mut header_file = NamedTempFile::new().unwrap();
    writeln!(header_file, r#"{{"typ": "JWT", "kid": "key-123"}}"#).unwrap();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("encode")
        .arg("--payload-file")
        .arg(payload_file.path())
        .arg("--header-file")
        .arg(header_file.path())
        .arg("--secret")
        .arg("secret")
        .assert()
        .success();
}

#[test]
fn test_encode_with_algorithm_override() {
    let mut payload_file = NamedTempFile::new().unwrap();
    writeln!(payload_file, r#"{{"sub": "test"}}"#).unwrap();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("encode")
        .arg("--payload-file")
        .arg(payload_file.path())
        .arg("--secret")
        .arg("secret")
        .arg("--algorithm")
        .arg("HS512")
        .assert()
        .success();
}

#[test]
fn test_encode_no_secret_provided() {
    let mut payload_file = NamedTempFile::new().unwrap();
    writeln!(payload_file, r#"{{"sub": "test"}}"#).unwrap();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("encode")
        .arg("--payload-file")
        .arg(payload_file.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("No secret or key provided"));
}

#[test]
fn test_encode_invalid_payload_json() {
    let mut payload_file = NamedTempFile::new().unwrap();
    writeln!(payload_file, "invalid json {{").unwrap();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("encode")
        .arg("--payload-file")
        .arg(payload_file.path())
        .arg("--secret")
        .arg("secret")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to parse payload JSON"));
}

#[test]
fn test_encode_roundtrip_decode() {
    // Create a token with encode, then decode it to verify
    let mut payload_file = NamedTempFile::new().unwrap();
    writeln!(
        payload_file,
        r#"{{"sub": "1234567890", "name": "Test User"}}"#
    )
    .unwrap();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    let output = cmd
        .arg("encode")
        .arg("--payload-file")
        .arg(payload_file.path())
        .arg("--secret")
        .arg("test-secret")
        .output()
        .unwrap();

    assert!(output.status.success());
    let token = String::from_utf8(output.stdout).unwrap();
    let token = token.trim();

    // Now decode it
    let mut decode_cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    decode_cmd
        .arg("decode")
        .arg(token)
        .assert()
        .success()
        .stdout(predicate::str::contains("Test User"))
        .stdout(predicate::str::contains("1234567890"));
}

#[test]
fn test_encode_roundtrip_validate() {
    // Create a token with encode, then validate it
    let mut payload_file = NamedTempFile::new().unwrap();
    writeln!(payload_file, r#"{{"sub": "test"}}"#).unwrap();

    let secret = "my-test-secret";

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    let output = cmd
        .arg("encode")
        .arg("--payload-file")
        .arg(payload_file.path())
        .arg("--secret")
        .arg(secret)
        .output()
        .unwrap();

    assert!(output.status.success());
    let token = String::from_utf8(output.stdout).unwrap();
    let token = token.trim();

    // Now validate it with the same secret
    let mut validate_cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    validate_cmd
        .arg("validate")
        .arg("--secret")
        .arg(secret)
        .arg(token)
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));
}

#[test]
fn test_encode_from_secret_file() {
    let mut payload_file = NamedTempFile::new().unwrap();
    writeln!(payload_file, r#"{{"sub": "test"}}"#).unwrap();

    let mut secret_file = NamedTempFile::new().unwrap();
    writeln!(secret_file, "file-secret-key").unwrap();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("jetta"));
    cmd.arg("encode")
        .arg("--payload-file")
        .arg(payload_file.path())
        .arg("--secret-file")
        .arg(secret_file.path())
        .assert()
        .success();
}
