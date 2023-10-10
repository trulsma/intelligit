use std::{
    collections::{hash_map::Entry, HashMap},
    path::PathBuf,
    rc::Rc,
};

use crate::diff;
use crate::git;
use crate::parser::{PatternListMatcher, PatternMatch};
use anyhow::Context;
use colored::Colorize;
use git::RepositoryExt;
use itertools::Itertools;

use crate::cli::command::{DiffCommand, GlobalOpts};

struct MatchWithNovelLines {
    lhs_match: Option<Rc<PatternMatch>>,
    rhs_match: Option<Rc<PatternMatch>>,
    novel_lhs: Vec<u32>,
    novel_rhs: Vec<u32>,
}

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

    for change in diff {
        match change {
            git::DiffResult::Added { path, content } => {
                if let Some(pattern) = matcher.pattern_for_file_path(&path) {
                    let matches = pattern.matches(&content, None, None)?;

                    println!("{} {} {path}", "+".green(), "file".bright_blue());
                    for mtch in matches {
                        println!(
                            "  {} {} {}",
                            "+".green(),
                            mtch.kind.bright_blue(),
                            mtch.full_qualifiers
                                .join(&pattern.qualifier_settings.seperator)
                        );
                    }
                } else {
                    println!(
                        "{} {} {}, no pattern found..",
                        "+".green(),
                        "file".bright_blue(),
                        path
                    );
                }
            }
            git::DiffResult::Deleted { path, content } => {
                if let Some(pattern) = matcher.pattern_for_file_path(&path) {
                    let matches = pattern.matches(&content, None, None)?;

                    println!("{} {} {path}", "-".red(), "file".bright_blue());
                    for mtch in matches {
                        println!(
                            "  {} {} {}",
                            "-".red(),
                            mtch.kind.bright_blue(),
                            mtch.full_qualifiers
                                .join(&pattern.qualifier_settings.seperator)
                        );
                    }
                } else {
                    println!(
                        "{} {} {}, no pattern found..",
                        "-".red(),
                        "file".bright_blue(),
                        path
                    );
                }
            }
            git::DiffResult::Modified {
                path,
                before_content,
                after_content,
            } => {
                let (novel_lhs, novel_rhs) = diff::diff(&before_content, &after_content);

                if let Some(pattern) = matcher.pattern_for_file_path(&path) {
                    println!(
                        "{} {} {path} (-{}, +{})",
                        "~".purple(),
                        "file".bright_blue(),
                        novel_lhs.len().to_string().red(),
                        novel_rhs.len().to_string().green()
                    );

                    let mut lhs = pattern
                        .matches(&before_content, None, None)?
                        .into_iter()
                        .sorted_by_key(|mtch| mtch.range_byte_count())
                        .map(|mtch| (mtch, vec![]))
                        .collect_vec();

                    for line in novel_lhs {
                        for (mtch, novel) in lhs.iter_mut() {
                            if mtch.contains_line(line as usize) {
                                novel.push(line);
                                // This has the same problems as earlier implementations in status.
                                // When an match is contained within a single line.
                                if !command.include_children {
                                    break;
                                }
                            }
                        }
                    }

                    // Could reuse tree from lhs and apply changes.. skipped for now, difference
                    // probably small
                    let mut rhs = pattern
                        .matches(&after_content, None, None)?
                        .into_iter()
                        .sorted_by_key(|mtch| mtch.range_byte_count())
                        .map(|mtch| (mtch, vec![]))
                        .collect_vec();

                    for line in novel_rhs {
                        for (mtch, novel) in rhs.iter_mut() {
                            if mtch.contains_line(line as usize) {
                                novel.push(line);
                                if !command.include_children {
                                    break;
                                }
                            }
                        }
                    }

                    let mut changes: HashMap<_, _> = lhs
                        .into_iter()
                        .map(|(mtch, novel)| {
                            (
                                mtch.full_qualifiers.clone(),
                                MatchWithNovelLines {
                                    lhs_match: Some(mtch),
                                    rhs_match: None,
                                    novel_lhs: novel,
                                    novel_rhs: vec![],
                                },
                            )
                        })
                        .collect();

                    for (mtch, novel) in rhs {
                        match changes.entry(mtch.full_qualifiers.clone()) {
                            Entry::Occupied(mut entry) => {
                                let entry = entry.get_mut();
                                entry.rhs_match = Some(mtch);
                                entry.novel_rhs = novel;
                            }

                            Entry::Vacant(entry) => {
                                entry.insert(MatchWithNovelLines {
                                    lhs_match: None,
                                    rhs_match: Some(mtch),
                                    novel_lhs: vec![],
                                    novel_rhs: novel,
                                });
                            }
                        };
                    }

                    for change in changes.values().filter(|change| {
                        !change.novel_lhs.is_empty() || !change.novel_rhs.is_empty()
                    }) {
                        // TODO: Calculate checksum and compare if lhs and rhs is changed
                        let mtch = change
                            .rhs_match
                            .as_ref()
                            .or(change.lhs_match.as_ref())
                            .expect("lhs or rhs must be set.");

                        let op = match (&change.lhs_match, &change.rhs_match) {
                            (None, Some(_)) => "+".green(),
                            (Some(_), None) => "-".red(),
                            (_, _) => "~".purple(),
                        };
                        let novel_lhs_count = change.novel_lhs.len();
                        let novel_rhs_count = change.novel_rhs.len();
                        println!(
                            "  {} {} {} (-{}, +{})",
                            op,
                            mtch.kind.bright_blue(),
                            mtch.full_qualifiers
                                .join(&pattern.qualifier_settings.seperator),
                            novel_lhs_count.to_string().red(),
                            novel_rhs_count.to_string().green()
                        );
                    }
                } else {
                    println!(
                        "{} {} {path} (-{}, +{}), no pattern found..",
                        "~".purple(),
                        "file".bright_blue(),
                        novel_lhs.len().to_string().red(),
                        novel_rhs.len().to_string().green()
                    );
                }
            }
        }
    }

    Ok(())
}
