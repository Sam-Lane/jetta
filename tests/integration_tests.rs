use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

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
