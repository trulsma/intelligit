pub mod command;
pub mod diff;
pub mod history;
pub mod logger;
pub mod pattern;
pub mod status;

use crate::parser::PatternListMatcher;
use anyhow::Context;
use clap::{ColorChoice, Parser};
use colored::Colorize;
use command::{App, GlobalOpts, ParserSubcommands, Subcommands};
use diff::handle_diff_command;
use history::handle_history_subcommand;
use pattern::handle_pattern_subcommand;
use status::print_status;
use std::path::PathBuf;

fn print_symbols(path: &str, global_opts: &GlobalOpts) -> anyhow::Result<()> {
    let metadata = std::fs::metadata(path).context(format!("Did not find {path}"))?;

    let files = if metadata.is_file() {
        vec![path.to_owned()]
    } else {
        let mut builder = ignore::WalkBuilder::new(path);
        builder.hidden(false);

        builder
            .build()
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.file_type().map_or(false, |ft| ft.is_file()))
            .filter_map(|entry| {
                let entry_path = entry.path();

                if entry_path.starts_with(format!("{path}/.git")) {
                    None
                } else {
                    entry_path.to_str().map(std::borrow::ToOwned::to_owned)
                }
            })
            .collect()
    };

    let mut matcher = PatternListMatcher::new(PathBuf::from(&global_opts.parser_path));

    crate::cli::pattern::load_patterns_from_opts(&mut matcher, global_opts)?;

    for file in files {
        let pattern = match matcher.pattern_for_file_path(&file) {
            Some(pattern) => pattern,
            None => continue,
        };

        println!("{}", file.bright_black());

        let data = std::fs::read(&file).context(format!("Failed to read content from {file}"))?;

        let matches = pattern.matches(&data, None, None)?;

        for mtch in matches {
            print!(
                "{} {}",
                mtch.kind.bright_blue(),
                mtch.full_qualifiers
                    .join(&pattern.qualifier_settings.seperator)
                    .white()
            );
            for range in mtch.ranges.borrow().iter() {
                print!(
                    " ({}-{})",
                    range.start_point.row + 1,
                    range.end_point.row + 1
                );
            }
            println!();
        }
    }

    Ok(())
}

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
    }
}
