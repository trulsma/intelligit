use crate::cli::command::{GlobalOpts, PatternSubcommands};
use crate::parser::{CreatePatternListError, PatternIdentifier, PatternListMatcher};
use anyhow::Context;
use colored::Colorize;
use std::path::PathBuf;

pub(crate) fn handle_pattern_subcommand(
    command: &PatternSubcommands,
    global_opts: &GlobalOpts,
) -> anyhow::Result<()> {
    match command {
        PatternSubcommands::List => list_patterns(global_opts),
        PatternSubcommands::Verify => verify_patterns(global_opts),
    }
}

pub(crate) fn print_load_pattern_results(
    load_pattern_result: Vec<(PatternIdentifier, Result<(), CreatePatternListError>)>,
) {
    for (identifier, res) in load_pattern_result {
        match res {
            Ok(_) => log::info!("{} loaded successfully", identifier),
            Err(err) => {
                log::warn!("{} loaded unsuccessfully: {}", identifier, err.to_string());
            }
        }
    }
}

pub(crate) fn load_patterns_from_opts(
    matcher: &mut PatternListMatcher,
    global_opts: &GlobalOpts,
) -> anyhow::Result<()> {
    if !global_opts.no_default_patterns {
        let load_pattern_results = matcher
            .load_default_patterns()
            .context("Failed to load core patterns")?;

        crate::cli::pattern::print_load_pattern_results(load_pattern_results);
    }

    if let Some(patterns_path) = &global_opts.patterns_path {
        let load_pattern_results = matcher
            .load_patterns(patterns_path)
            .context(format!("Failed to load patterns from {}", patterns_path))?;

        crate::cli::pattern::print_load_pattern_results(load_pattern_results);
    }

    Ok(())
}

fn list_patterns(global_opts: &GlobalOpts) -> anyhow::Result<()> {
    let mut matcher = PatternListMatcher::new(PathBuf::from(&global_opts.parser_path));

    load_patterns_from_opts(&mut matcher, global_opts)?;

    let indent = "  ";
    for pattern in matcher.patterns {
        println!("{}", format!("{}", pattern.identifier).bright_black());
        println!(
            "{}parser: {}",
            indent,
            format!("{:?}", pattern.parser).bright_black()
        );
        println!(
            "{}{} symbol patterns",
            indent,
            format!("{:?}", pattern.patterns.len()).bright_blue()
        );
    }

    Ok(())
}

fn verify_patterns(global_opts: &GlobalOpts) -> anyhow::Result<()> {
    let parser_path = PathBuf::from(&global_opts.parser_path);
    let mut matcher = PatternListMatcher::new(parser_path);

    crate::cli::pattern::load_patterns_from_opts(&mut matcher, global_opts)?;

    if matcher.patterns.is_empty() {
        println!("Found no patterns to verify..");
    } else {
        for pattern in matcher.patterns {
            match pattern.verify() {
                Ok(_) => println!("{} ok", format!("{}", pattern.identifier).bright_green()),
                Err(error) => {
                    println!("{}", format!("{}", pattern.identifier).bright_red());

                    println!("  - {}", error);
                }
            }
        }
    }

    Ok(())
}
