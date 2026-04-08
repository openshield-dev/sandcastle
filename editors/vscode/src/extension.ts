import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";

let statusBarItem: vscode.StatusBarItem;
let auditLogWatcher: vscode.FileSystemWatcher | undefined;
let monitorPanel: vscode.WebviewPanel | undefined;

export function activate(context: vscode.ExtensionContext) {
  const config = vscode.workspace.getConfiguration("sandcastle");
  const binaryPath = config.get<string>("binaryPath", "sandcastle");

  // Status bar item
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBarItem.command = "sandcastle.monitor";
  context.subscriptions.push(statusBarItem);
  updateStatusBar();

  // File system watcher for audit log
  const workspaceRoot = getWorkspaceRoot();
  if (workspaceRoot) {
    const pattern = new vscode.RelativePattern(
      workspaceRoot,
      ".sandcastle/audit.log"
    );
    auditLogWatcher = vscode.workspace.createFileSystemWatcher(pattern);
    auditLogWatcher.onDidChange(() => refreshMonitorPanel(workspaceRoot));
    auditLogWatcher.onDidCreate(() => {
      updateStatusBar();
      refreshMonitorPanel(workspaceRoot);
    });
    auditLogWatcher.onDidDelete(() => updateStatusBar());
    context.subscriptions.push(auditLogWatcher);
  }

  // Command: Open Monitor
  context.subscriptions.push(
    vscode.commands.registerCommand("sandcastle.monitor", () => {
      const root = getWorkspaceRoot();
      if (!root) {
        vscode.window.showWarningMessage("No workspace folder open.");
        return;
      }

      if (monitorPanel) {
        monitorPanel.reveal();
        refreshMonitorPanel(root);
        return;
      }

      monitorPanel = vscode.window.createWebviewPanel(
        "sandcastleMonitor",
        "SandCastle Monitor",
        vscode.ViewColumn.One,
        { enableScripts: false }
      );

      monitorPanel.onDidDispose(() => {
        monitorPanel = undefined;
      });

      refreshMonitorPanel(root);
    })
  );

  // Command: Undo Last Run
  context.subscriptions.push(
    vscode.commands.registerCommand("sandcastle.undo", () => {
      const terminal = vscode.window.createTerminal("SandCastle Undo");
      terminal.show();
      terminal.sendText(`${binaryPath} undo --yes`);
    })
  );

  // Command: Show Run Diff
  context.subscriptions.push(
    vscode.commands.registerCommand("sandcastle.diff", async () => {
      const outputChannel =
        vscode.window.createOutputChannel("SandCastle Diff");
      outputChannel.show(true);
      outputChannel.appendLine("Running sandcastle diff...\n");

      try {
        const { exec } = await import("child_process");
        const root = getWorkspaceRoot();
        exec(
          `${binaryPath} diff`,
          { cwd: root ?? undefined },
          (error, stdout, stderr) => {
            if (stdout) {
              outputChannel.appendLine(stdout);
            }
            if (stderr) {
              outputChannel.appendLine(stderr);
            }
            if (error) {
              outputChannel.appendLine(`Exit code: ${error.code}`);
            }
          }
        );
      } catch (err) {
        outputChannel.appendLine(`Failed to run sandcastle diff: ${err}`);
      }
    })
  );

  // Command: Run Command in Sandbox
  context.subscriptions.push(
    vscode.commands.registerCommand("sandcastle.run", async () => {
      const command = await vscode.window.showInputBox({
        prompt: "Enter the command to run inside the sandbox",
        placeHolder: "e.g. npm test",
      });

      if (!command) {
        return;
      }

      const profile = config.get<string>("defaultProfile", "develop");
      const terminal = vscode.window.createTerminal("SandCastle Run");
      terminal.show();
      terminal.sendText(
        `${binaryPath} run --profile ${profile} -- ${command}`
      );
    })
  );

  // Auto-open monitor if configured and .sandcastle exists
  if (config.get<boolean>("autoMonitor", true) && workspaceRoot) {
    const sandcastleDir = path.join(workspaceRoot, ".sandcastle");
    if (fs.existsSync(sandcastleDir)) {
      vscode.commands.executeCommand("sandcastle.monitor");
    }
  }
}

export function deactivate() {
  monitorPanel?.dispose();
  statusBarItem?.dispose();
  auditLogWatcher?.dispose();
}

function getWorkspaceRoot(): string | null {
  const folders = vscode.workspace.workspaceFolders;
  return folders && folders.length > 0 ? folders[0].uri.fsPath : null;
}

function updateStatusBar() {
  const root = getWorkspaceRoot();
  if (root && fs.existsSync(path.join(root, ".sandcastle"))) {
    statusBarItem.text = "$(shield) SandCastle: Active";
    statusBarItem.tooltip = "Click to open SandCastle Monitor";
    statusBarItem.show();
  } else {
    statusBarItem.hide();
  }
}

function refreshMonitorPanel(workspaceRoot: string) {
  if (!monitorPanel) {
    return;
  }

  const auditLogPath = path.join(workspaceRoot, ".sandcastle", "audit.log");
  let logContent = "(no audit log found)";

  if (fs.existsSync(auditLogPath)) {
    try {
      const raw = fs.readFileSync(auditLogPath, "utf-8");
      // Show the last 200 lines to keep the view manageable
      const lines = raw.split("\n");
      const tail = lines.slice(-200).join("\n");
      logContent = escapeHtml(tail);
    } catch {
      logContent = "(failed to read audit log)";
    }
  }

  monitorPanel.webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <style>
    body { font-family: var(--vscode-editor-font-family, monospace); font-size: 13px; padding: 12px; background: var(--vscode-editor-background); color: var(--vscode-editor-foreground); }
    h1 { font-size: 16px; margin-bottom: 8px; }
    pre { white-space: pre-wrap; word-wrap: break-word; }
  </style>
</head>
<body>
  <h1>SandCastle Audit Log</h1>
  <pre>${logContent}</pre>
</body>
</html>`;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
