# list all just reciepes
@default:
    just -l

# format all code to rust std.
fmt:
    cargo fmt --all

# run clippy on all targets and features include warnings
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

# run all tests
test:
    cargo test --all-features
