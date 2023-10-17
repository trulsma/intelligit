use std::path::PathBuf;

use anyhow::Context;
use colored::Colorize;

use crate::cli::command::OutputFormat;
use crate::parser::PatternListMatcher;

use super::command::GlobalOpts;

#[derive(serde::Serialize)]
struct Symbol {
    kind: String,
    qualifiers: String,
    file_path: String,
}

#[derive(serde::Serialize)]
struct Output {
    symbols: Vec<Symbol>,
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
        let symbols = pattern.matches(&data, None, None)?;
        for symbol in symbols {
            output.symbols.push(Symbol {
                kind: symbol.kind.to_string(),
                qualifiers: symbol
                    .full_qualifiers
                    .join(&pattern.qualifier_settings.seperator),
                file_path: file.clone(),
            });
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
