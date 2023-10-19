use colored::Colorize;

use crate::{datastore, git};

use super::command::{LogCommand, GlobalOpts, OutputFormat};

pub(crate) fn handle_log_command(
    command: LogCommand,
    global_opts: &GlobalOpts,
) -> anyhow::Result<()> {
    if let (None, None, None) = (&command.file, &command.kind, &command.qualifiers) {
        anyhow::bail!("file, kind or qualifier must be set.");
    }


    let datastore = datastore::open(&command.datastore_opts.datastore_path)?;

    let repo = git::open("./")?;
    crate::cli::history::assert_history_updated(&repo, &datastore, false, false)?;

    let symbols = datastore::query_symbols(
        &datastore,
        command.file.as_deref(),
        command.kind.as_deref(),
        command.qualifiers.as_deref(),
    )?;

    let symbol = match &symbols[..] {
        [symbol] => symbol.clone(),
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
                id: String
            }

            let output: anyhow::Result<Vec<_>>  = commits.into_iter().map(|db_commit| {
                let commit = repo.find_object(db_commit.id.as_slice())?.into_commit();
                let time_format = time::macros::format_description!("[day].[month].[year]");
                let time_formatted = commit.decode()?.author.time.format(time_format);
                let message = commit.message()?;
                let body = message.body().map(|b| b.to_string());
                let title = message.title.to_string();
                let id = commit.id.to_hex().to_string();
                Ok(OutputCommit { id, title, body, seconds_since_epoch: db_commit.seconds_since_epoch, time_formatted,  })
            }).collect();
            print!("{}", serde_json::to_string_pretty(&output?)?);
        },
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