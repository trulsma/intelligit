use crate::cli::command::{GlobalOpts, StatusArgs};
use crate::git::RepositoryExt;
use crate::git::{self, IndexEntryList, TreeEntryList};
use crate::parser::symbol::SymbolChange;
use crate::parser::PatternListMatcher;
use anyhow::Context;
use colored::Colorize;
use itertools::Itertools;
use std::path::PathBuf;

use super::command::OutputFormat;

pub(crate) fn print_status(args: &StatusArgs, global_opts: &GlobalOpts) -> anyhow::Result<()> {
    let repo = git::open(args.repo.as_str()).context("Failed to open git repository")?;

    let untracked_entries = repo
        .untracked_entries()
        .context("Found no local file entries..")?;

    let staged_entries = repo
        .staged_entries()
        .unwrap_or_else(IndexEntryList::new_empty);

    let head_entries = repo
        .head_commit()
        .ok()
        .and_then(|commit| repo.commit_entries(&commit))
        .unwrap_or_else(TreeEntryList::new_empty);

    let mut matcher = PatternListMatcher::new(PathBuf::from(&global_opts.parser_path));

    crate::cli::pattern::load_patterns_from_opts(&mut matcher, global_opts)?;

    let untracked_staged_diff = (
        vec![],
        git::diff(&staged_entries, &untracked_entries).collect_vec(),
    );
    let staged_head_diff = (
        vec![],
        git::diff(&head_entries, &staged_entries).collect_vec(),
    );

    let mut diffs = [untracked_staged_diff, staged_head_diff];

    for (ref mut symbols, diff) in diffs.iter_mut() {
        for change in diff {
            match change {
                git::DiffResult::Added { path, content } => {
                    symbols.extend(crate::parser::diff::diff_file(
                        path,
                        &matcher,
                        None,
                        Some(content),
                        args.include_children,
                    )?)
                }
                git::DiffResult::Deleted { path, content } => {
                    symbols.extend(crate::parser::diff::diff_file(
                        path,
                        &matcher,
                        Some(content),
                        None,
                        args.include_children,
                    )?)
                }
                git::DiffResult::Modified {
                    path,
                    before_content,
                    after_content,
                } => symbols.extend(crate::parser::diff::diff_file(
                    path,
                    &matcher,
                    Some(before_content),
                    Some(after_content),
                    args.include_children,
                )?),
            }
        }
    }

    let [(untracked_staged_diff, _), (staged_head_diff, _)] = diffs;

    match global_opts.format {
        OutputFormat::Json => {
            #[derive(serde::Serialize)]
            struct Output {
                untracked_staged_diff: Vec<SymbolChange>,
                staged_head_diff: Vec<SymbolChange>,
            }

            let output = Output {
                untracked_staged_diff,
                staged_head_diff,
            };
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputFormat::Text => {
            if staged_head_diff.is_empty() && untracked_staged_diff.is_empty() {
                println!("No changes");
                return Ok(());
            }

            for (header, symbols) in [
                ("Staged:", staged_head_diff),
                ("Untracked:", untracked_staged_diff),
            ] {
                if !symbols.is_empty() {
                    println!("{header}");
                }

                for (file_change, changes) in
                    crate::parser::symbol::group_symbol_changes_by_files(symbols)
                {
                    let (op, path) = match file_change {
                        SymbolChange::Added { symbol, .. } => {
                            ("+", symbol.file_path.green())
                        }
                        SymbolChange::Deleted { symbol, .. } => {
                            ("-", symbol.file_path.bright_red())
                        }
                        SymbolChange::Modified { symbol, .. } => {
                            ("~", symbol.file_path.bright_purple())
                        }
                    };
                    println!("{} {}", op,  path);
                    for change in changes {
                        match change {
                            SymbolChange::Added { symbol, .. } => println!(
                                "  {} {} {}",
                                "+".white(),
                                symbol.kind.bright_blue(),
                                symbol.qualifiers.green(),
                            ),
                            SymbolChange::Deleted { symbol, .. } => println!(
                                "  {} {} {}",
                                "-".white(),
                                symbol.kind.bright_blue(),
                                symbol.qualifiers.bright_red(),
                            ),
                            SymbolChange::Modified { symbol, .. } => println!(
                                "  {} {} {}",
                                "~".white(),
                                symbol.kind.bright_blue(),
                                symbol.qualifiers.bright_purple(),
                            ),
                        }
                    }
                }
            }
        }
    }
    Ok(())
}


