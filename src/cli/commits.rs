use std::path::PathBuf;

use colored::Colorize;

use crate::{
    datastore, git,
    parser::{symbol::Symbol, PatternListMatcher},
};

use super::{
    command::{GlobalOpts, LogCommand, OutputFormat},
    symbols::find_symbol_by_file_and_location,
};

pub(crate) fn handle_log_command(
    command: LogCommand,
    global_opts: &GlobalOpts,
) -> anyhow::Result<()> {
    let datastore = datastore::open(&command.datastore_opts.datastore_path)?;

    let repo = git::open("./")?;
    // crate::cli::history::assert_history_updated(&repo, &datastore, false, false)?;

    let symbol = match (
        command.file.as_deref(),
        command.kind.as_deref(),
        command.qualifiers.as_deref(),
        command.row,
        command.column,
    ) {
        (Some(file), None, None, Some(row), Some(column)) => {
            let mut matcher = PatternListMatcher::new(PathBuf::from(&global_opts.parser_path));
            crate::cli::pattern::load_patterns_from_opts(&mut matcher, global_opts)?;
            let location = tree_sitter::Point { row, column };
            find_symbol_by_file_and_location(file, location, &matcher)?
        }
        (Some(_), None, None, Some(_), _) | (Some(_), None, None, _, Some(_)) => {
            anyhow::bail!("Both row and column must be set.")
        }
        (None, None, None, _, _) => anyhow::bail!("file, kind or qualifier must be set."),
        (None, _, _, Some(_), _) | (None, _, _, _, Some(_)) => {
            anyhow::bail!("row and column can only be used in combination with file")
        }
        (Some(_), _, _, Some(_), _) | (Some(_), _, _, _, Some(_)) => {
            anyhow::bail!("kind or qualifiers can not be used in combination with row and column")
        }
        (file, kind, qualifiers, None, None) => {
            let symbols = datastore::query_symbols(&datastore, file, kind, qualifiers)?;
            match &symbols[..] {
                [symbol] => Symbol {
                    file_path: symbol.file_path.clone(),
                    kind: symbol.kind.clone(),
                    qualifiers: symbol.qualifiers.clone(),
                },
                [] => {
                    println!("Found no symbols..");
                    return Ok(());
                }
                symbols => {
                    println!("Found more than one symbol..");
                    for symbol in symbols {
                        println!(
                            "{} {} {}",
                            symbol.kind.bright_blue(),
                            symbol.qualifiers.bright_yellow(),
                            symbol.file_path.bright_black()
                        );
                    }

                    return Ok(());
                }
            }
        }
    };

    let Symbol {
        file_path,
        kind,
        qualifiers,
    } = symbol;
    let symbol = crate::datastore::Symbol {
        file_path,
        kind,
        qualifiers,
    };

    let mut commits = datastore::symbol_commits(&datastore, &symbol)?;
    commits.sort_by_key(|c| std::cmp::Reverse(c.seconds_since_epoch));

    match global_opts.format {
        OutputFormat::Json => {
            #[derive(serde::Serialize)]
            struct OutputCommit {
                seconds_since_epoch: i64,
                time_formatted: String,
                title: String,
                body: Option<String>,
                id: String,
            }

            let output: anyhow::Result<Vec<_>> = commits
                .into_iter()
                .map(|db_commit| {
                    let commit = repo.find_object(db_commit.id.as_slice())?.into_commit();
                    let time_format = time::macros::format_description!("[day].[month].[year]");
                    let time_formatted = commit.decode()?.author.time.format(time_format);
                    let message = commit.message()?;
                    let body = message.body().map(|b| b.to_string());
                    let title = message.title.to_string();
                    let id = commit.id.to_hex().to_string();
                    Ok(OutputCommit {
                        id,
                        title,
                        body,
                        seconds_since_epoch: db_commit.seconds_since_epoch,
                        time_formatted,
                    })
                })
                .collect();
            print!("{}", serde_json::to_string_pretty(&output?)?);
        }
        OutputFormat::Text => {
            fn without_trailing_newline(mut string: String) -> String {
                if string.ends_with('\n') {
                    string.pop();
                    if string.ends_with('\r') {
                        string.pop();
                    }
                }
                string
            }

            println!(
                "{} {} {}",
                symbol.kind.bright_blue(),
                symbol.qualifiers.bright_yellow(),
                symbol.file_path.bright_black()
            );

            for commit in commits {
                let commit = repo.find_object(commit.id.as_slice())?.into_commit();
                let time_format = time::macros::format_description!("[day].[month].[year]");
                let time = commit.decode()?.author.time.format(time_format);
                let message = commit.message()?;
                let title = without_trailing_newline(message.title.to_string());
                let id = commit.id.to_hex_with_len(8).to_string();
                println!(
                    "{} {} {}",
                    id.bright_black(),
                    time.bright_blue(),
                    title.white()
                );
            }
        }
    }

    Ok(())
}
