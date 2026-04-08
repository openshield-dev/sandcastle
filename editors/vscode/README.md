# SandCastle VS Code Extension

Monitor and control AI agent sandboxes directly from VS Code.

## Features

- **Monitor** -- Live audit log viewer that auto-refreshes when the log changes
- **Undo** -- Revert the last sandboxed run with one command
- **Diff** -- View filesystem changes made during a sandboxed run
- **Run** -- Execute arbitrary commands inside a sandbox from the command palette
- **Status Bar** -- Shows "SandCastle: Active" when a `.sandcastle/` directory exists
- **Activity Bar** -- Sidebar panels for Activity, Blocked Operations, and Snapshots

## Commands

| Command | Description |
|---------|-------------|
| `SandCastle: Open Monitor` | Opens a webview with the live audit log |
| `SandCastle: Undo Last Run` | Runs `sandcastle undo --yes` in a terminal |
| `SandCastle: Show Run Diff` | Runs `sandcastle diff` and shows output |
| `SandCastle: Run Command in Sandbox` | Prompts for a command, runs it sandboxed |

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `sandcastle.defaultProfile` | `develop` | Security profile for sandboxed runs |
| `sandcastle.autoMonitor` | `true` | Auto-open monitor when a sandbox starts |
| `sandcastle.binaryPath` | `sandcastle` | Path to the sandcastle binary |

## Install from Source

```bash
cd editors/vscode
npm install
npm run compile
```

Then press **F5** in VS Code to launch an Extension Development Host, or package it:

```bash
npm run package
code --install-extension sandcastle-0.1.0.vsix
```

## Requirements

- VS Code 1.85.0 or later
- The `sandcastle` CLI binary installed and on your PATH (or configured via `sandcastle.binaryPath`)
