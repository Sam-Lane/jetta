<!-- OPENSPEC:START -->
# OpenSpec Instructions

These instructions are for AI assistants working in this project.

Always open `@/openspec/AGENTS.md` when the request:
- Mentions planning or proposals (words like proposal, spec, change, plan)
- Introduces new capabilities, breaking changes, architecture shifts, or big performance/security work
- Sounds ambiguous and you need the authoritative spec before coding

Use `@/openspec/AGENTS.md` to learn:
- How to create and apply change proposals
- Spec format and conventions
- Project structure and guidelines

Keep this managed block so 'openspec update' can refresh the instructions.

<!-- OPENSPEC:END -->

## Jetta-Specific Agent Instructions


### Mandatory Branching Stratedgy.
**ALWAYS** either start a new branch for a feature or ask for clarification if this should be on an existing branch. Never commit or work directly on `main`

### Mandatory Quality Checks

**CRITICAL**: Before marking ANY task as complete or creating ANY commit, you MUST run and pass these checks:

```bash
# Run ALL of these checks - they must ALL pass
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

**Why this matters:**
- Our CI uses `-D warnings` which treats clippy warnings as hard errors
- We've broken CI multiple times by not running these checks before committing
- These are the EXACT same settings our GitHub Actions CI uses

**Workflow:**
1. Make code changes
2. Run `cargo fmt --all` to auto-format
3. Run `cargo clippy --all-targets --all-features -- -D warnings` - must pass with ZERO warnings
4. Run `cargo test` - all tests must pass
5. ONLY THEN commit and mark task complete

**If clippy fails:**
- Fix ALL warnings (they will be errors in CI)
- Re-run the full check suite
- Do NOT commit until everything passes

### Common Clippy Issues

- **Deprecated functions**: Use recommended alternatives from warning messages
- **Unused imports**: Remove them
- **Needless borrows**: Follow clippy suggestions
- **Type complexity**: Refactor if suggested

### CI/CD Settings

Our `.github/workflows/ci.yml` runs:
- `cargo fmt --all -- --check` (formatting)
- `cargo clippy --all-targets --all-features -- -D warnings` (linting, warnings = errors)
- `cargo test --all-features` (tests)

Always match these settings locally before pushing.