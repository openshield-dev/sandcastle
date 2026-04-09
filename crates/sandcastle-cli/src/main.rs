#![forbid(unsafe_code)]
//! SandCastle command-line interface.

use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(name = "sandcastle")]
#[command(version)]
#[command(about = "Secure sandbox runtime for local AI agents", long_about = None)]
#[command(after_help = "Part of the OpenShield ecosystem — https://openshield.dev")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output format (text, json)
    #[arg(long, global = true, default_value = "text")]
    format: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a command inside a sandbox
    Run {
        /// Security profile to use
        #[arg(long, default_value = "develop")]
        profile: String,

        /// Allow read access to additional directories
        #[arg(long = "allow-dir")]
        allow_dirs: Vec<String>,

        /// Allow network access to specific domains
        #[arg(long = "allow-net")]
        allow_net: Vec<String>,

        /// Allow GPU access
        #[arg(long)]
        allow_gpu: bool,

        /// Interactive mode (permission prompts)
        #[arg(short, long)]
        interactive: bool,

        /// Audit mode (log but don't block)
        #[arg(long = "mode", default_value = "enforce")]
        mode: String,

        /// Command to run (everything after --)
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Manage sandbox snapshots
    Snapshot {
        #[command(subcommand)]
        action: SnapshotCommands,
    },

    /// Policy management
    Policy {
        #[command(subcommand)]
        action: PolicyCommands,
    },

    /// View audit logs
    Audit {
        /// Show only the last N events
        #[arg(long)]
        last: Option<usize>,

        /// Show only violations
        #[arg(long)]
        violations_only: bool,

        /// Export format (json, csv, text)
        #[arg(long)]
        export: Option<String>,

        /// Path to audit log file
        #[arg(long)]
        file: Option<String>,
    },

    /// Manage security profiles
    Profiles {
        #[command(subcommand)]
        action: ProfileCommands,
    },

    /// Initialize a sandcastle.yaml in the current directory
    Init {
        /// Base profile to use
        #[arg(long)]
        profile: Option<String>,
    },

    /// Live monitoring dashboard for sandbox activity
    Monitor {
        /// Path to audit log file
        #[arg(long)]
        file: Option<String>,
    },

    /// Show what changed during the last sandbox run
    Diff {
        /// Path to audit log file
        #[arg(long)]
        file: Option<String>,
        /// Compare against a named snapshot
        #[arg(long)]
        snapshot: Option<String>,
    },

    /// Undo the last sandbox run (restore pre-run snapshot)
    Undo {
        /// Skip confirmation prompt
        #[arg(long, short)]
        yes: bool,
    },

    /// Compare two sandbox runs side-by-side
    Compare {
        /// Audit log file for run A
        #[arg(long)]
        log_a: String,
        /// Audit log file for run B
        #[arg(long)]
        log_b: String,
        /// Profile name (for display)
        #[arg(long, default_value = "develop")]
        profile: String,
    },

    /// Show risk assessment for a sandbox run
    Risk {
        /// Path to audit log file
        #[arg(long)]
        file: Option<String>,
        /// Filter to a specific session ID
        #[arg(long)]
        session: Option<String>,
        /// Maximum acceptable risk score (exit 1 if exceeded)
        #[arg(long)]
        max_score: Option<u8>,
    },

    /// Search and install community sandbox profiles
    Registry {
        #[command(subcommand)]
        action: RegistryCommands,
    },
}

#[derive(Subcommand)]
enum RegistryCommands {
    /// Search for profiles by name or keyword
    Search {
        /// Search query
        query: String,
    },
    /// Install a profile locally
    Install {
        /// Profile name
        name: String,
    },
    /// Publish a profile to the community registry
    Publish {
        /// Path to the profile YAML file
        file: String,
    },
}

#[derive(Subcommand)]
enum SnapshotCommands {
    /// Create a snapshot
    Create {
        /// Snapshot name
        name: String,
        /// Description
        #[arg(short, long)]
        description: Option<String>,
    },
    /// List snapshots
    List,
    /// Show diff since snapshot
    Diff {
        /// Snapshot name to compare against
        name: String,
    },
    /// Restore a snapshot
    Restore {
        /// Snapshot name
        name: String,
    },
    /// Create a branch from a snapshot
    Branch {
        /// Source snapshot name
        source: String,
        /// New branch name
        name: String,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Generate policy from audit log
    Generate {
        /// Path to audit log
        #[arg(long = "from-audit")]
        from_audit: String,
    },
    /// Validate a policy file
    Validate {
        /// Path to policy file
        file: String,
    },
    /// Show a profile's effective policy
    Show {
        /// Profile name
        #[arg(long)]
        profile: String,
    },
}

#[derive(Subcommand)]
enum ProfileCommands {
    /// List available profiles
    List,
    /// Show profile details
    Show {
        /// Profile name
        name: String,
    },
    /// Create a custom profile
    Create {
        /// Profile name
        name: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialise tracing subscriber — verbose flag controls log level.
    let level = if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::WARN
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .init();

    match cli.command {
        Commands::Run {
            profile,
            allow_dirs,
            allow_net,
            allow_gpu,
            interactive,
            mode,
            command,
        } => {
            commands::run::execute(
                &profile,
                &allow_dirs,
                &allow_net,
                allow_gpu,
                interactive,
                &mode,
                &command,
            )?;
        }

        Commands::Snapshot { action } => match action {
            SnapshotCommands::Create { name, description } => {
                commands::snapshot::create(&name, description.as_deref())?;
            }
            SnapshotCommands::List => {
                commands::snapshot::list()?;
            }
            SnapshotCommands::Diff { name } => {
                commands::snapshot::diff(&name)?;
            }
            SnapshotCommands::Restore { name } => {
                commands::snapshot::restore(&name)?;
            }
            SnapshotCommands::Branch { source, name } => {
                commands::snapshot::branch(&source, &name)?;
            }
        },

        Commands::Policy { action } => match action {
            PolicyCommands::Generate { from_audit } => {
                commands::policy::generate(&from_audit)?;
            }
            PolicyCommands::Validate { file } => {
                commands::policy::validate(&file)?;
            }
            PolicyCommands::Show { profile } => {
                commands::policy::show(&profile)?;
            }
        },

        Commands::Audit {
            last,
            violations_only,
            export,
            file,
        } => {
            commands::audit::execute(last, violations_only, export.as_deref(), file.as_deref())?;
        }

        Commands::Profiles { action } => match action {
            ProfileCommands::List => {
                commands::profiles::list()?;
            }
            ProfileCommands::Show { name } => {
                commands::profiles::show(&name)?;
            }
            ProfileCommands::Create { name } => {
                commands::profiles::create(&name)?;
            }
        },

        Commands::Monitor { file } => {
            commands::monitor::execute(file.as_deref())?;
        }

        Commands::Init { profile } => {
            commands::init::execute(profile.as_deref())?;
        }

        Commands::Diff { file, snapshot } => {
            commands::diff::execute(file.as_deref(), snapshot.as_deref())?;
        }

        Commands::Undo { yes } => {
            commands::undo::execute(yes)?;
        }

        Commands::Compare {
            log_a,
            log_b,
            profile,
        } => {
            commands::compare::execute(
                &[log_a],
                &[log_b],
                &profile,
            )?;
        }

        Commands::Risk {
            file,
            session,
            max_score,
        } => {
            if let Some(max) = max_score {
                let passed = commands::risk::execute_with_threshold(
                    file.as_deref(),
                    session.as_deref(),
                    max,
                )?;
                if !passed {
                    std::process::exit(1);
                }
            } else {
                commands::risk::execute(file.as_deref(), session.as_deref())?;
            }
        }

        Commands::Registry { action } => match action {
            RegistryCommands::Search { query } => {
                commands::registry::search(&query)?;
            }
            RegistryCommands::Install { name } => {
                commands::registry::install(&name)?;
            }
            RegistryCommands::Publish { file } => {
                commands::registry::publish(&file)?;
            }
        },
    }

    Ok(())
}
