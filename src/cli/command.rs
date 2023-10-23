use clap::{Args, ColorChoice, Parser};

#[derive(Debug, clap::ValueEnum, Clone, Copy)]
pub(crate) enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Off,
}

impl From<LogLevel> for log::LevelFilter {
    fn from(val: LogLevel) -> Self {
        match val {
            LogLevel::Trace => log::LevelFilter::Trace,
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Error => log::LevelFilter::Error,
            LogLevel::Off => log::LevelFilter::Off,
        }
    }
}

#[derive(Debug, clap::ValueEnum, Clone, Copy)]
pub enum OutputFormat {
    /// Human readable text
    Text,
    /// Json
    Json,
}

#[derive(Debug, Args)]
pub(crate) struct GlobalOpts {
    /// Color output. Ignored if format is not 'text'
    #[clap(long, global = true, default_value_t = ColorChoice::Auto)]
    pub(crate) color: ColorChoice,

    /// Directory to look for and store parsers
    #[clap(long = "parsers", global = true, default_value = ".intelligit")]
    pub(crate) parser_path: String,

    /// Directory to look for patterns
    #[clap(long = "patterns", global = true, default_value = None)]
    pub(crate) patterns_path: Option<String>,

    /// Directory to store and query data
    #[clap(long = "datastore", global = true, default_value = ".intelligit")]
    pub(crate) datastore_path: String,

    /// Skip loading default patterns
    #[clap(long, global = true, default_value_t = false)]
    pub(crate) no_default_patterns: bool,

    #[clap(long = "log", global = true, default_value = "error")]
    pub(crate) loglevel: LogLevel,

    /// Output format
    #[clap(long, global = true, default_value = "text")]
    pub(crate) format: OutputFormat,
}

#[derive(Debug, Parser)]
#[command(version)]
pub(crate) struct App {
    #[clap(flatten)]
    pub(crate) global_opts: GlobalOpts,

    #[clap(subcommand)]
    pub(crate) subcommand: Subcommands,
}

#[derive(Debug, clap::Args)]
pub(crate) struct StatusArgs {
    #[clap(default_value = "./")]
    pub(crate) repo: String,

    /// Include match if children is changed
    #[arg(long, default_value_t = false)]
    pub include_children: bool,
    // Possible arguments: expand_added_files, expand_deleted_files (dont show matches for some
    // files to avoid too long status output?)
}

#[derive(Debug, clap::Subcommand)]
pub(crate) enum Subcommands {
    /// Show staged and untracked changes
    Status(StatusArgs),

    /// For history specific commands
    History(History),

    /// Display all symbols for a file or directory
    Symbols {
        #[clap(default_value = "./")]
        path: String,
    },
    /// For parser specific commands
    #[clap(subcommand)]
    Parser(ParserSubcommands),

    /// For pattern specific commands
    #[clap(subcommand)]
    Pattern(PatternSubcommands),

    /// Diff to commits
    Diff(DiffCommand),

    /// Find commits for a symbol
    Log(LogCommand),
}

#[derive(Debug, clap::ValueEnum, Clone, Copy)]
pub(crate) enum DiffFormat {
    Minimal,
    Detailed,
}

#[derive(Debug, clap::Args)]
pub(crate) struct DiffCommand {
    pub before: Option<String>,
    pub after: Option<String>,

    /// Include match if children is changed
    #[arg(long, default_value_t = false)]
    pub include_children: bool,
}

#[derive(Debug, clap::Args)]
pub(crate) struct BuildHistoryArgs {
    #[clap(default_value = "./")]
    pub(crate) repo: String,
    #[clap(long, default_value_t = bytesize::ByteSize::mb(200))]
    pub(crate) cache_size: bytesize::ByteSize,
    /// Delete all history before trying to build
    #[clap(long, default_value_t = false)]
    pub(crate) rebuild: bool,
}

#[derive(Debug, clap::Args)]
pub(crate) struct InspectHistoryArgs {
    #[clap(long, short = 'f', default_value = None)]
    pub(crate) file: Option<String>,
    #[clap(long, short = 'k', default_value = None)]
    pub(crate) kind: Option<String>,
    #[clap(long, short = 'q', default_value = None)]
    pub(crate) qualifiers: Option<String>,
    /// Column of symbol, zero indexed
    #[clap(long, short ='c', default_value = None)]
    pub(crate) column: Option<usize>,
    /// Row of symbol, zero indexed
    #[clap(long, short = 'r', default_value = None)]
    pub(crate) row: Option<usize>,
}

#[derive(Debug, clap::Args)]
pub(crate) struct LogCommand {
    #[clap(long, short = 'f', default_value = None)]
    pub(crate) file: Option<String>,
    #[clap(long, short = 'k', default_value = None)]
    pub(crate) kind: Option<String>,
    #[clap(long, short = 'q', default_value = None)]
    pub(crate) qualifiers: Option<String>,
    /// Column of symbol, zero indexed
    #[clap(long, short ='c', default_value = None)]
    pub(crate) column: Option<usize>,
    /// Row of symbol, zero indexed
    #[clap(long, short = 'r', default_value = None)]
    pub(crate) row: Option<usize>,
}

#[derive(Debug, Args)]
pub(crate) struct History {
    #[clap(flatten)]
    pub(crate) opts: HistoryOpts,
    #[clap(subcommand)]
    pub(crate) subcommand: HistorySubcommands,
}

#[derive(Debug, Args)]
pub(crate) struct HistoryOpts {
    /// Directory to look for patterns
    #[clap(long = "datastore", global = true, default_value = ".intelligit")]
    pub(crate) datastore_path: String,
}

#[derive(Debug, clap::Subcommand)]
pub(crate) enum HistorySubcommands {
    /// Build the history
    Build(BuildHistoryArgs),
    /// Inspect history for a symbol
    Inspect(InspectHistoryArgs),
    /// List all changes
    Changes,
}

#[derive(Debug, clap::Subcommand)]
pub(crate) enum ParserSubcommands {
    /// List all installed parsers
    List,
}

#[derive(Debug, clap::Subcommand)]
pub(crate) enum PatternSubcommands {
    /// List all patterns
    List,
    /// Verify patterns
    Verify,
}
