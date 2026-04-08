# Contributing to SandCastle

Thank you for your interest in contributing to SandCastle!

## Getting Started

```bash
git clone https://github.com/openshield-dev/sandcastle.git
cd sandcastle
cargo build --workspace
cargo test --workspace
```

## Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run checks: `cargo clippy --workspace -- -D warnings && cargo fmt --check && cargo test --workspace`
5. Commit with a descriptive message
6. Open a pull request

## Code Standards

- **Rust edition**: 2021
- **Formatting**: `cargo fmt` (see `.rustfmt.toml`)
- **Linting**: `cargo clippy -- -D warnings`
- **Safety**: `#![forbid(unsafe_code)]` on all crates except `sandcastle-platform`
- **Tests**: Every security fix must include a regression test

## Architecture

```
sandcastle-cli          ← User-facing CLI
├── sandcastle-platform ← OS-specific isolation (Linux/macOS/Windows)
├── sandcastle-fs       ← Filesystem isolation (overlay, bind, guard)
├── sandcastle-network  ← Network filtering (DNS, egress, TLS)
├── sandcastle-gpu      ← GPU passthrough management
├── sandcastle-snapshot ← Snapshot/branch/restore
├── sandcastle-audit    ← Audit logging and export
└── sandcastle-policy   ← Policy definitions, trust levels, profiles
```

## Adding a New Agent Profile

1. Add the profile to `crates/sandcastle-policy/src/profile.rs`
2. Add auto-detection in `crates/sandcastle-policy/src/resolver.rs` (COMMAND_MAP)
3. Add tests for the new profile
4. Update README.md with the new agent

## Security

- Never commit secrets or credentials
- All filesystem paths must be validated against traversal attacks
- Deny rules always take priority over allow rules
- See [SECURITY.md](SECURITY.md) for reporting vulnerabilities
