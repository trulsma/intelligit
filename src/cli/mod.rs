pub mod command;
pub mod diff;
pub mod commits;
pub mod history;
pub mod logger;
pub mod pattern;
pub mod status;
pub mod symbols;
pub mod add;

use clap::{ColorChoice, Parser};
use command::{App, GlobalOpts, ParserSubcommands, Subcommands};
use diff::handle_diff_command;
use history::handle_history_subcommand;
use pattern::handle_pattern_subcommand;
use symbols::print_symbols;
use status::print_status;
use commits::handle_log_command;

use self::add::handle_add_command;

fn list_parsers(_global_opts: &GlobalOpts) -> anyhow::Result<()> {
    todo!("List parsers")
}

pub fn main_impl() -> anyhow::Result<()> {
    let args = App::parse();

    match args.global_opts.color {
        ColorChoice::Never => {
            colored::control::set_override(false);
        }
        ColorChoice::Always => {
            colored::control::set_override(true);
        }
        ColorChoice::Auto => {}
    };

    if let Err(err) = logger::Logger::init() {
        anyhow::bail!("Failed to initialize logging {}", err);
    }
    log::set_max_level(args.global_opts.loglevel.into());

    match args.subcommand {
        Subcommands::Status(status_args) => print_status(&status_args, &args.global_opts),
        Subcommands::History(subcommand) => {
            handle_history_subcommand(&subcommand, &args.global_opts)
        }
        Subcommands::Symbols { path } => print_symbols(&path, &args.global_opts),
        Subcommands::Pattern(subcommand) => {
            handle_pattern_subcommand(&subcommand, &args.global_opts)
        }
        Subcommands::Parser(ParserSubcommands::List) => list_parsers(&args.global_opts),
        Subcommands::Diff(command) => handle_diff_command(command, &args.global_opts),
        Subcommands::Log(command) => handle_log_command(command, &args.global_opts),
        Subcommands::Add(command) => handle_add_command(command, &args.global_opts)
    }
}
