# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-02-25

### Added
- **Homebrew distribution support**: Install via `brew install sam-lane/tap/jetta`
- Automated Homebrew cask publishing to `sam-lane/homebrew-tap`
- GoReleaser-based release automation for better package manager integration
- Interactive mode with animated welcome screen
- `--no-animation` flag to skip the welcome animation
- Explicit stdin support via `-` argument for `decode` and `validate` commands
- "Common Errors" section in README with troubleshooting guidance

### Changed
- **BREAKING**: Binary artifact naming convention changed from `jetta-{target}.tar.gz` to `jetta_{version}_{os}_{arch}.tar.gz`
  - Old: `jetta-x86_64-unknown-linux-gnu.tar.gz`
  - New: `jetta_1.0.0_linux_amd64.tar.gz`
  - **Migration**: If you have automation that downloads binaries, update to the new naming pattern
- **BREAKING**: Token argument is now required for `decode` and `validate` commands
- **BREAKING**: To read from stdin, you must now explicitly use `-` as the token argument (e.g., `echo $TOKEN | jetta decode -`)
- Release process migrated from taiki-e actions to GoReleaser
- File flag (`--file`) now takes precedence over token argument
- Help text updated to clarify stdin usage with `-`

### Fixed
- Fixed confusing UX where running `jetta decode` without arguments would silently wait for stdin with no prompt or feedback

## [0.1.0] - 2026-02-25

### Added
- Initial development version
