use crate::cli::command::{GlobalOpts, StatusArgs};
use crate::diff;
use crate::git::{self, IndexEntryList, TreeEntryList};
use crate::git::RepositoryExt;
use crate::parser::{PatternList, PatternListMatcher, PatternMatch};
use anyhow::Context;
use colored::Colorize;
use std::{collections::HashSet, path::PathBuf, rc::Rc};

pub(crate) fn print_status(args: &StatusArgs, global_opts: &GlobalOpts) -> anyhow::Result<()> {
    let repo = git::open(args.repo.as_str()).context("Failed to open git repository")?;

    let untracked_entries = repo
        .untracked_entries()
        .context("Found no local file entries..")?;

    let staged_entries = repo.staged_entries().unwrap_or_else(IndexEntryList::new_empty);

    let head_entries = repo.head_commit().ok().and_then(|commit| repo.commit_entries(&commit)).unwrap_or_else(TreeEntryList::new_empty);

    let staged_untracked_diff: Vec<_> = git::diff(&staged_entries, &untracked_entries).collect();
    let head_staged_diff: Vec<_> = git::diff(&head_entries, &staged_entries).collect();

    if head_staged_diff.is_empty() && staged_untracked_diff.is_empty() {
        println!("No changes..");
        return Ok(());
    }

    let mut matcher = PatternListMatcher::new(PathBuf::from(&global_opts.parser_path));

    crate::cli::pattern::load_patterns_from_opts(&mut matcher, global_opts)?;

    if !head_staged_diff.is_empty() {
        println!("Staged:");

        for file in &head_staged_diff {
            if let git::DiffResult::Added { path, content } = file {
                match matcher.pattern_for_file_path(path) {
                    Some(pattern) => {
                        let matches = match pattern.matches(content, None, None) {
                            Ok(matches) => matches,
                            Err(e) => {
                                println!(
                                    "{} {} ({} {})",
                                    "+".green(),
                                    path.green(),
                                    "Pattern matching failed...".bright_black(),
                                    e
                                );
                                continue;
                            }
                        };
                        println!("{} {}", "+".green(), path.green(),);

                        for mtch in matches {
                            println!(
                                "  + {} {}",
                                mtch.kind.bright_blue(),
                                mtch.full_qualifiers
                                    .join(&pattern.qualifier_settings.seperator)
                                    .bright_green()
                            );
                        }
                    }
                    None => println!(
                        "{} {} {}",
                        "+".green(),
                        path.green(),
                        "(No pattern found)".bright_black()
                    ),
                }
            }
        }
        for file in &head_staged_diff {
            if let git::DiffResult::Deleted { path, .. } = file {
                println!("{} {}", "-".red(), path.green());
            }
        }
        for file in &head_staged_diff {
            if let git::DiffResult::Modified {
                path,
                before_content,
                after_content,
            } = file
            {
                match diff_matches(&matcher, path, before_content, after_content) {
                    Some((pattern, mut changes)) => {
                        changes.sort_by_key(|diff| match diff {
                            PatternMatchDiff::Added(mtch) => mtch.range_first_byte(),
                            PatternMatchDiff::Deleted(mtch) => mtch.range_first_byte(),
                            PatternMatchDiff::Modified { before, .. } => before.range_first_byte(),
                        });

                        println!("{} {}", "~".purple(), path.green());
                        for change in changes {
                            match change {
                                PatternMatchDiff::Added(mtch) => println!(
                                    "  + {} {}",
                                    mtch.kind.bright_blue(),
                                    mtch.full_qualifiers
                                        .join(&pattern.qualifier_settings.seperator)
                                        .bright_green()
                                ),
                                PatternMatchDiff::Deleted(mtch) => println!(
                                    "  - {} {}",
                                    mtch.kind.bright_blue(),
                                    mtch.full_qualifiers
                                        .join(&pattern.qualifier_settings.seperator)
                                        .bright_red()
                                ),
                                PatternMatchDiff::Modified { before, .. } => println!(
                                    "  ~ {} {}",
                                    before.kind.bright_blue(),
                                    before
                                        .full_qualifiers
                                        .join(&pattern.qualifier_settings.seperator)
                                        .bright_magenta()
                                ),
                            }
                        }
                    }
                    None => println!(
                        "{} {} {}",
                        "~".purple(),
                        path.green(),
                        "(No pattern found)".bright_black()
                    ),
                }
            }
        }
        println!();
    }

    if !staged_untracked_diff.is_empty() {
        println!("Untracked:");

        for file in &staged_untracked_diff {
            if let git::DiffResult::Added { path, .. } = file {
                println!("{} {}", "+".green(), path.bright_blue());
            }
        }
        for file in &staged_untracked_diff {
            if let git::DiffResult::Deleted { path, .. } = file {
                println!("{} {}", "-".red(), path.bright_blue());
            }
        }
        for file in &staged_untracked_diff {
            if let git::DiffResult::Modified {
                path,
                before_content,
                after_content,
            } = file
            {
                match diff_matches(&matcher, path, before_content, after_content) {
                    Some((pattern, mut changes)) => {
                        changes.sort_by_key(|diff| match diff {
                            PatternMatchDiff::Added(mtch) => mtch.range_first_byte(),
                            PatternMatchDiff::Deleted(mtch) => mtch.range_first_byte(),
                            PatternMatchDiff::Modified { before, .. } => before.range_first_byte(),
                        });

                        println!("{} {}", "~".purple(), path.green());
                        for change in changes {
                            match change {
                                PatternMatchDiff::Added(mtch) => println!(
                                    "  + {} {}",
                                    mtch.kind.bright_blue(),
                                    mtch.full_qualifiers
                                        .join(&pattern.qualifier_settings.seperator)
                                        .bright_green()
                                ),
                                PatternMatchDiff::Deleted(mtch) => println!(
                                    "  - {} {}",
                                    mtch.kind.bright_blue(),
                                    mtch.full_qualifiers
                                        .join(&pattern.qualifier_settings.seperator)
                                        .bright_red()
                                ),
                                PatternMatchDiff::Modified { before, .. } => println!(
                                    "  ~ {} {}",
                                    before.kind.bright_blue(),
                                    before
                                        .full_qualifiers
                                        .join(&pattern.qualifier_settings.seperator)
                                        .bright_magenta()
                                ),
                            }
                        }
                    }
                    None => println!(
                        "{} {} {}",
                        "~".purple(),
                        path.green(),
                        "(No pattern found)".bright_black()
                    ),
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
enum PatternMatchDiff {
    Added(Rc<PatternMatch>),
    Deleted(Rc<PatternMatch>),
    Modified {
        before: Rc<PatternMatch>,
        #[allow(dead_code)]
        after: Rc<PatternMatch>,
    },
}

fn diff_matches<'a>(
    pattern_matcher: &'a PatternListMatcher,
    path: &str,
    before_content: &[u8],
    after_content: &[u8],
) -> Option<(&'a PatternList, Vec<PatternMatchDiff>)> {
    let pattern = pattern_matcher.pattern_for_file_path(path)?;

    let mut tree = pattern.parse(before_content, None).ok()?;

    let lhs = pattern.matches(before_content, Some(&tree), None).ok()?;

    let changes = diff::changes(before_content, after_content);
    for change in changes {
        tree.edit(&change);
    }

    let rhs = pattern.matches(after_content, None, Some(&tree)).ok()?;

    let qualifiers: HashSet<_> = lhs
        .iter()
        .map(|mtch| &mtch.full_qualifiers)
        .chain(rhs.iter().map(|mtch| &mtch.full_qualifiers))
        .cloned()
        .collect();

    let diff = qualifiers
        .into_iter()
        .map(|full_qualifiers| {
            (
                lhs.iter()
                    .find(|mtch| mtch.full_qualifiers == full_qualifiers),
                rhs.iter()
                    .find(|mtch| mtch.full_qualifiers == full_qualifiers),
            )
        })
        .filter_map(|matches| match matches {
            (Some(lhs), Some(rhs)) => {
                if lhs.checksum(before_content) != rhs.checksum(after_content) {
                    Some(PatternMatchDiff::Modified {
                        before: lhs.clone(),
                        after: rhs.clone(),
                    })
                } else {
                    None
                }
            }
            (Some(lhs), None) => Some(PatternMatchDiff::Deleted(lhs.clone())),
            (None, Some(rhs)) => Some(PatternMatchDiff::Added(rhs.clone())),
            (None, None) => None,
        })
        .collect();

    Some((pattern, diff))
}
