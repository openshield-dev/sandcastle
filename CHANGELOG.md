# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Initial project structure with 8 crates
- Policy engine with 5 trust levels (Explore → Unrestricted)
- Pre-built profiles for Claude Code, Codex, Ollama, LangChain
- Network filtering with domain allowlists, egress control, TLS verification
- Filesystem isolation with OverlayFS, bind mounts, copy-on-write
- Snapshot/branch/restore for sandbox state management
- Audit logging with sequence numbers, rate limiting, CSV/JSON export
- GPU passthrough management (nvproxy, VFIO, GPU-PV)
- CLI with profile management, policy generation, audit viewing
- GitHub Actions CI (check, test, clippy, fmt, security audit)
- Cross-platform support (Linux stable, macOS/Windows beta)

### Security
- Path traversal prevention in filesystem operations
- Symlink following blocked in recursive directory operations
- Private/reserved IP blocking (SSRF prevention)
- Cloud metadata endpoint blocking at all trust levels
- Input validation for CLI arguments (names, paths, domains)
- Sensitive environment variable filtering
- Audit log sanitization against injection attacks
- CSV formula injection prevention in exports
- `#![forbid(unsafe_code)]` on 7 of 8 crates

## [0.1.0] - 2026-04-08

Initial release.
