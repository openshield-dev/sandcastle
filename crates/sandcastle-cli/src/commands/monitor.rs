//! Real-time TUI dashboard for monitoring sandbox activity.

use std::io::{self, Stdout};
use std::time::{Duration, Instant};

use anyhow::Context;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Terminal;
use sandcastle_audit::event::{EventType, PolicyDecision};
use sandcastle_audit::AuditEvent;

/// Drop guard that restores the terminal even on panic.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = io::stdout().execute(LeaveAlternateScreen);
    }
}

struct DashboardState {
    events: Vec<AuditEvent>,
    scroll_offset: usize,
    violations_only: bool,
}

impl DashboardState {
    fn new() -> Self {
        Self { events: Vec::new(), scroll_offset: 0, violations_only: false }
    }

    /// Maximum audit file size to read (10 MB). Prevents DoS on large logs.
    const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

    fn load_events(&mut self, path: &std::path::Path) -> anyhow::Result<()> {
        // Check file size before reading to prevent OOM on large logs.
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        if meta.len() > Self::MAX_FILE_SIZE {
            // Read only the tail of the file (last MAX_FILE_SIZE bytes).
            use std::io::{Read, Seek, SeekFrom};
            let mut f = std::fs::File::open(path)?;
            f.seek(SeekFrom::End(-(Self::MAX_FILE_SIZE as i64)))?;
            let mut raw = String::new();
            f.read_to_string(&mut raw)?;
            // Drop the first (likely partial) line.
            if let Some(idx) = raw.find('\n') {
                raw = raw[idx + 1..].to_string();
            }
            self.events = raw.lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| serde_json::from_str::<AuditEvent>(l).ok())
                .collect();
        } else {
            let raw = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => return Ok(()),
            };
            self.events = raw.lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| serde_json::from_str::<AuditEvent>(l).ok())
                .collect();
        }
        // Clamp scroll offset to valid range after reload.
        let max = self.events.len().saturating_sub(1);
        if self.scroll_offset > max {
            self.scroll_offset = max;
        }
        Ok(())
    }

    fn filtered_events(&self) -> Vec<&AuditEvent> {
        if self.violations_only {
            self.events.iter().filter(|e| e.is_violation()).collect()
        } else {
            self.events.iter().collect()
        }
    }

    fn blocked_count(&self) -> usize {
        self.events.iter().filter(|e| e.is_violation()).count()
    }

    fn allowed_count(&self) -> usize {
        self.events.iter().filter(|e| e.is_allowed()).count()
    }

    fn fs_ops(&self) -> usize {
        self.events.iter().filter(|e| is_fs_event(&e.event_type)).count()
    }

    fn net_ops(&self) -> usize {
        self.events.iter().filter(|e| is_net_event(&e.event_type)).count()
    }

    fn last_blocked(&self, n: usize) -> Vec<&AuditEvent> {
        self.events.iter().filter(|e| e.is_violation()).rev().take(n).collect()
    }

    fn header_info(&self) -> (String, String, String) {
        match self.events.last() {
            Some(last) => (
                last.sandbox_id.clone(),
                last.context.profile.clone().unwrap_or_else(|| "default".into()),
                last.context.trust_level.clone().unwrap_or_else(|| "unknown".into()),
            ),
            None => ("N/A".into(), "N/A".into(), "N/A".into()),
        }
    }
}

fn is_fs_event(et: &EventType) -> bool {
    matches!(et, EventType::FilesystemRead | EventType::FilesystemWrite
        | EventType::FilesystemDelete | EventType::FilesystemCreate)
}

fn is_net_event(et: &EventType) -> bool {
    matches!(et, EventType::NetworkConnect | EventType::NetworkRequest
        | EventType::NetworkDnsResolve)
}

fn event_type_tag(et: &EventType) -> &'static str {
    if is_fs_event(et) { "FS" }
    else if is_net_event(et) { "NET" }
    else if matches!(et, EventType::ProcessExec | EventType::ProcessSpawn) { "PROC" }
    else { "OTHER" }
}

fn event_target(evt: &AuditEvent) -> String {
    evt.action.path.clone()
        .or_else(|| evt.action.domain.clone())
        .or_else(|| evt.action.command.clone())
        .unwrap_or_else(|| evt.action.description.clone())
}

fn truncate(s: String, max: usize) -> String {
    if s.len() > max { format!("{}...", &s[..max - 3]) } else { s }
}

fn decision_span(decision: &PolicyDecision) -> Span<'static> {
    match decision {
        PolicyDecision::Allow | PolicyDecision::AuditOnly =>
            Span::styled(" \u{2713} ", Style::default().fg(Color::Green)),
        PolicyDecision::Deny | PolicyDecision::AskHuman =>
            Span::styled(" \u{2717} ", Style::default().fg(Color::Red)),
    }
}

fn make_activity_item(evt: &AuditEvent) -> ListItem<'static> {
    let ts = evt.timestamp.format("%H:%M:%S").to_string();
    let tag = event_type_tag(&evt.event_type);
    let target = truncate(event_target(evt), 60);
    let decision = decision_span(&evt.policy_result.decision);
    ListItem::new(Line::from(vec![
        Span::styled(format!("{ts} "), Style::default().fg(Color::DarkGray)),
        Span::styled(format!("[{tag:>5}] "), Style::default().fg(Color::Blue)),
        Span::raw(format!("{target} ")),
        decision,
    ]))
}

fn make_blocked_item(evt: &AuditEvent) -> ListItem<'static> {
    let ts = evt.timestamp.format("%H:%M:%S").to_string();
    let tag = event_type_tag(&evt.event_type);
    let target = truncate(event_target(evt), 50);
    ListItem::new(Line::from(vec![
        Span::styled(format!("{ts} "), Style::default().fg(Color::DarkGray)),
        Span::styled(format!("[{tag}] "), Style::default().fg(Color::Red)),
        Span::styled(target, Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
    ]))
}

fn render(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: &DashboardState,
) -> anyhow::Result<()> {
    terminal.draw(|frame| {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // header
                Constraint::Length(3),  // stats bar
                Constraint::Min(8),    // activity feed
                Constraint::Length(12), // blocked panel
            ])
            .split(frame.area());

        // Header
        let (sandbox_id, profile, trust) = state.header_info();
        let header = Paragraph::new(format!(
            "SandCastle Monitor  |  Sandbox: {sandbox_id}  |  Profile: {profile}  |  Trust: {trust}"
        ))
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL));
        frame.render_widget(header, chunks[0]);

        // Stats bar
        let filter_tag = if state.violations_only { "  [FILTER: violations only]" } else { "" };
        let stats = Paragraph::new(format!(
            "Total: {}  |  Blocked: {}  |  Allowed: {}  |  FS ops: {}  |  Net ops: {}{}",
            state.events.len(), state.blocked_count(), state.allowed_count(),
            state.fs_ops(), state.net_ops(), filter_tag,
        ))
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().title(" Stats ").borders(Borders::ALL));
        frame.render_widget(stats, chunks[1]);

        // Activity feed
        let filtered = state.filtered_events();
        let vis = chunks[2].height.saturating_sub(2) as usize;
        let total = filtered.len();
        let off = state.scroll_offset.min(total.saturating_sub(vis));
        let items: Vec<ListItem> = filtered.iter().skip(off).take(vis)
            .map(|e| make_activity_item(e)).collect();
        let title = format!(
            " Activity [{}-{} of {total}] (Up/Down scroll, f=filter, q=quit) ",
            off + 1, (off + vis).min(total),
        );
        frame.render_widget(
            List::new(items).block(Block::default().title(title).borders(Borders::ALL)),
            chunks[2],
        );

        // Blocked panel
        let blocked: Vec<ListItem> = state.last_blocked(10).iter()
            .map(|e| make_blocked_item(e)).collect();
        frame.render_widget(
            List::new(blocked).block(
                Block::default()
                    .title(" Blocked (last 10) ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red)),
            ),
            chunks[3],
        );
    })?;
    Ok(())
}

/// Run the real-time TUI monitor dashboard.
///
/// Reads audit events from `audit_file` (defaulting to `.sandcastle/audit.log`)
/// and renders a live dashboard that refreshes every 500ms.
pub fn execute(audit_file: Option<&str>) -> anyhow::Result<()> {
    let log_path = match audit_file {
        Some(f) => std::path::PathBuf::from(f),
        None => std::env::current_dir()
            .context("Failed to determine current directory")?
            .join(".sandcastle/audit.log"),
    };

    enable_raw_mode().context("Failed to enable raw mode")?;
    io::stdout().execute(EnterAlternateScreen).context("Failed to enter alternate screen")?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).context("Failed to create terminal")?;
    let mut state = DashboardState::new();
    let poll_interval = Duration::from_millis(500);

    loop {
        state.load_events(&log_path)?;
        render(&mut terminal, &state)?;

        let deadline = Instant::now() + poll_interval;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if event::poll(remaining).context("Failed to poll for events")? {
                if let Event::Key(key) = event::read().context("Failed to read event")? {
                    if key.kind != KeyEventKind::Press { continue; }
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                        KeyCode::Up => state.scroll_offset = state.scroll_offset.saturating_sub(1),
                        KeyCode::Down => state.scroll_offset = state.scroll_offset.saturating_add(1),
                        KeyCode::Char('f') => {
                            state.violations_only = !state.violations_only;
                            state.scroll_offset = 0;
                        }
                        _ => {}
                    }
                    render(&mut terminal, &state)?;
                }
            }
        }
    }
}
