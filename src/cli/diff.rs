use std::path::PathBuf;

use crate::parser::PatternListMatcher;
use crate::{git, parser::symbol::SymbolChange};
use anyhow::Context;
use colored::Colorize;
use git::RepositoryExt;
use itertools::Itertools;

use crate::cli::command::{DiffCommand, GlobalOpts};

use super::command::OutputFormat;

pub(crate) fn handle_diff_command(
    command: DiffCommand,
    global_opts: &GlobalOpts,
) -> anyhow::Result<()> {
    let repo = git::open("./")?;

    let diff = match (command.before, command.after) {
        // Compare to commits
        (Some(before), Some(after)) => {
            let before_commit = repo
                .find_object_by_partial_hash(before)?
                .try_into_commit()?;
            let before_entries = repo
                .commit_entries(&before_commit)
                .context("Failed to get commit entries")?;

            let after_commit = repo.find_object_by_partial_hash(after)?.try_into_commit()?;

            let after_entries = repo
                .commit_entries(&after_commit)
                .context("Failed to get commit entries")?;

            git::diff(&before_entries, &after_entries).collect_vec()
        }
        // Compare working tree to commit
        (Some(commit), None) => {
            let commit = repo
                .find_object_by_partial_hash(commit)?
                .try_into_commit()?;
            let entries = repo
                .commit_entries(&commit)
                .context("Failed to get commit entries")?;

            let file_entries = repo
                .untracked_entries()
                .context("Faield to get untracked entries")?;

            git::diff(&entries, &file_entries).collect_vec()
        }
        // Compare working tree and staging
        (None, None) => {
            let staged_entries = repo
                .staged_entries()
                .context("Failed to get staged entries")?;
            let file_entries = repo
                .untracked_entries()
                .context("Faield to get untracked entries")?;

            git::diff(&staged_entries, &file_entries).collect_vec()
        }
        (None, Some(_after)) => {
            unreachable!("Before and after is positional arguements so this combo is impossible.")
        }
    };

    let mut matcher = PatternListMatcher::new(PathBuf::from(&global_opts.parser_path));
    crate::cli::pattern::load_patterns_from_opts(&mut matcher, global_opts)?;

    let mut symbols = vec![];

    for change in diff {
        match change {
            git::DiffResult::Added { path, content } => {
                symbols.extend(crate::parser::diff::diff_file(
                    &path,
                    &matcher,
                    None,
                    Some(&content),
                    command.include_children,
                )?)
            }
            git::DiffResult::Deleted { path, content } => {
                symbols.extend(crate::parser::diff::diff_file(
                    &path,
                    &matcher,
                    Some(&content),
                    None,
                    command.include_children,
                )?)
            }
            git::DiffResult::Modified {
                path,
                before_content,
                after_content,
            } => symbols.extend(crate::parser::diff::diff_file(
                &path,
                &matcher,
                Some(&before_content),
                Some(&after_content),
                command.include_children,
            )?),
        }
    }

    match global_opts.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&symbols)?);
        }
        OutputFormat::Text => {
            for (file_change, changes) in
                crate::parser::symbol::group_symbol_changes_by_files(symbols)
            {
                let (op, path) = match file_change {
                    SymbolChange::Added { symbol, .. } => ("+".green(), symbol.file_path),
                    SymbolChange::Modified { symbol, .. } => ("~".purple(), symbol.file_path),
                    SymbolChange::Deleted { symbol, .. } => ("-".bright_red(), symbol.file_path),
                };
                println!("{} {}", op, path.bright_black());
                for change in changes {
                    match change {
                        SymbolChange::Added { symbol, .. } => println!(
                            "  {} {} {}",
                            "+".green(),
                            symbol.kind.bright_blue(),
                            symbol.qualifiers.bright_yellow(),
                        ),
                        SymbolChange::Deleted { symbol, .. } => println!(
                            "  {} {} {}",
                            "-".bright_red(),
                            symbol.kind.bright_blue(),
                            symbol.qualifiers.bright_yellow(),
                        ),
                        SymbolChange::Modified { symbol, .. } => println!(
                            "  {} {} {}",
                            "~".purple(),
                            symbol.kind.bright_blue(),
                            symbol.qualifiers.bright_yellow(),
                        ),
                    }
                }
            }
        }
    }
    Ok(())
}


