use colored::Colorize;

use crate::{datastore, git, parser::symbol::Symbol};

use super::{
    command::{GlobalOpts, LogCommand, OutputFormat},
    symbols::{find_symbol, SymbolFilter},
};

pub(crate) fn handle_log_command(
    command: LogCommand,
    global_opts: &GlobalOpts,
) -> anyhow::Result<()> {
    let datastore = datastore::open(&global_opts.datastore_path)?;

    let repo = git::open("./")?;
    // crate::cli::history::assert_history_updated(&repo, &datastore, false, false)?;

    let symbol = find_symbol(
        SymbolFilter {
            file_path: command.file.as_deref(),
            kind: command.kind.as_deref(),
            qualifiers: command.qualifiers.as_deref(),
            row: command.row,
            column: command.column,
        },
        None,
        Some(&datastore),
        global_opts,
    )?;

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

    let mut changes = datastore::changes_for_symbol(&datastore, &symbol)?;
    changes.sort_by_key(|c| std::cmp::Reverse(c.commit.seconds_since_epoch));

    match global_opts.format {
        OutputFormat::Json => {
            #[derive(serde::Serialize)]
            struct OutputCommit {
                seconds_since_epoch: i64,
                time_formatted: String,
                title: String,
                body: Option<String>,
                id: String,
                novel_lhs: u32,
                novel_rhs: u32,
                size_after: u64,
            }

            let output: anyhow::Result<Vec<_>> = changes
                .into_iter()
                .map(|change| {
                    let commit = repo.find_object(change.commit.id.as_slice())?.into_commit();
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
                        seconds_since_epoch: change.commit.seconds_since_epoch,
                        time_formatted,
                        novel_lhs: change.novel_lhs,
                        novel_rhs: change.novel_rhs,
                        size_after: change.size_after
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&output?)?);
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
                "{} {} in {}",
                symbol.kind.bright_blue(),
                symbol.qualifiers.bright_yellow(),
                symbol.file_path.bright_black()
            );

            for change in changes {
                let commit = repo.find_object(change.commit.id.as_slice())?.into_commit();
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
