# Using SandCastle in CI

## Basic Usage with Claude Code

Run Claude Code inside a sandboxed environment with the `claude-code` security profile:

```yaml
- name: Run Claude Code in sandbox
  uses: openshield/sandcastle@v1
  with:
    profile: claude-code
    command: claude --task "Refactor the auth module"
```

## Custom Permissions

Grant access to specific directories and network domains:

```yaml
- name: Run with custom permissions
  uses: openshield/sandcastle@v1
  with:
    profile: develop
    command: npm run build
    allow-dirs: ./dist,./node_modules
    allow-net: registry.npmjs.org,api.github.com
```

## Risk Score Threshold

Fail the workflow step if the risk score exceeds a threshold. Useful for
enforcing security standards in pull request checks:

```yaml
- name: Run with risk threshold
  uses: openshield/sandcastle@v1
  with:
    profile: claude-code
    command: claude --task "Add unit tests for utils"
    max-risk-score: '5'
```

If the sandboxed run produces a risk score above 5, the step fails and the
audit log is uploaded as an artifact for review.

## Audit Mode

Run in audit mode to log policy violations without blocking execution.
This is useful when evaluating a new profile before switching to enforcement:

```yaml
- name: Run in audit mode
  uses: openshield/sandcastle@v1
  with:
    profile: build
    command: make release
    mode: audit
```

The audit log is always uploaded as a GitHub Actions artifact, regardless of
whether the step passes or fails.

## Full Workflow Example

```yaml
name: Sandboxed CI
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Build in sandbox
        uses: openshield/sandcastle@v1
        with:
          profile: build
          command: cargo build --release
          max-risk-score: '3'

      - name: Test in sandbox
        uses: openshield/sandcastle@v1
        with:
          profile: develop
          command: cargo test
          allow-dirs: ./target
```

## Inputs Reference

| Input | Default | Description |
|-------|---------|-------------|
| `profile` | `develop` | Security profile (`claude-code`, `codex`, `ollama`, `develop`, `build`) |
| `command` | (required) | Command to run inside the sandbox |
| `allow-dirs` | `''` | Additional allowed directories (comma-separated) |
| `allow-net` | `''` | Additional allowed network domains (comma-separated) |
| `mode` | `enforce` | `enforce` blocks violations; `audit` logs them |
| `max-risk-score` | `10` | Fail if risk score exceeds this value (0-10) |
| `version` | `latest` | SandCastle version to install |
