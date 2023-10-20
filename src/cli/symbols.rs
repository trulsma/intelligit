use std::path::PathBuf;

use anyhow::Context;
use colored::Colorize;
use itertools::Itertools;

use crate::cli::command::OutputFormat;
use crate::parser::symbol::Symbol;
use crate::parser::PatternListMatcher;

use super::command::GlobalOpts;

#[derive(serde::Serialize)]
struct Output {
    symbols: Vec<Symbol>,
}

pub fn find_symbol_by_file_and_location(
    file_path: &str,
    location: tree_sitter::Point,
    matcher: &PatternListMatcher,
) -> anyhow::Result<Symbol> {
    let pattern = matcher
        .pattern_for_file_path(file_path)
        .context(format!("Found no pattern for {file_path}"))?;

    let data =
        std::fs::read(file_path).context(format!("Failed to read content from {file_path}"))?;
    let matches = pattern.matches(&data, None, None)?;

    matches
        .into_iter()
        .sorted_by_key(|mtch| mtch.range_byte_count())
        .find(|mtch| mtch.contains_point(location))
        .map(|mtch| Symbol::new(mtch, file_path, pattern))
        .context(format!(
            "Did not find a symbol at location {location} in {file_path}"
        ))
}

pub(crate) fn print_symbols(path: &str, global_opts: &GlobalOpts) -> anyhow::Result<()> {
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

    let mut output = Output { symbols: vec![] };

    for file in files {
        let pattern = match matcher.pattern_for_file_path(&file) {
            Some(pattern) => pattern,
            None => continue,
        };

        let data = std::fs::read(&file).context(format!("Failed to read content from {file}"))?;
        let matches = pattern.matches(&data, None, None)?;
        for mtch in matches {
            output.symbols.push(Symbol::new(mtch, &file, pattern));
        }
    }

    match global_opts.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputFormat::Text => {
            for symbol in output.symbols {
                println!(
                    "{} {} {}",
                    symbol.kind.bright_blue(),
                    symbol.qualifiers.bright_yellow(),
                    symbol.file_path.bright_black()
                );
            }
        }
    }

    Ok(())
}
