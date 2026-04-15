# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SandCastle, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

### How to Report

Email: monadsupreme@gmail.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Fix & Disclosure**: Coordinated with reporter, typically within 30 days

### Scope

The following are in scope:
- Sandbox escape vulnerabilities
- Policy bypass attacks
- Path traversal / symlink attacks
- Network filter bypass
- Privilege escalation
- Audit log tampering

### Current Limitations

SandCastle is under active development. The following are **known limitations**, not vulnerabilities:
- Linux enforcement (Landlock, seccomp, namespaces) is being implemented
- macOS sandbox-exec integration is in progress
- Windows AppContainer support is partial
- DNS resolution uses system resolver (not fully intercepted yet)

See the [README](README.md) for current platform support status.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Current |

## Security Design

SandCastle uses defense-in-depth with multiple independent isolation layers:

1. **Policy Layer** — Profile-based permissions (trust levels, allow/deny lists)
2. **Filesystem** — Landlock LSM, OverlayFS, bind mounts, FsGuard
3. **Network** — DNS interception, domain allowlists, egress control, TLS verification
4. **Syscalls** — seccomp-BPF filtering (Linux)
5. **Resources** — cgroup-v2 limits, Job Objects (Windows)
6. **Audit** — Tamper-evident logging with sequence numbers
