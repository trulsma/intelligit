use crate::cli::command::{GlobalOpts, StatusArgs};
use crate::diff;
use crate::git;
use crate::git::RepositoryExt;
use crate::parser::{PatternListMatcher, PatternMatch};
use anyhow::Context;
use colored::Colorize;
use std::{collections::HashSet, path::PathBuf, rc::Rc};

pub(crate) fn print_status(args: &StatusArgs, global_opts: &GlobalOpts) -> anyhow::Result<()> {
    let repo = git::open(args.repo.as_str()).context("Failed to open git repository")?;

    let untracked_entries = repo
        .untracked_entries()
        .context("Found no local file entries..")?;

    let staged_entries = repo.staged_entries().context("Found no index..")?;

    let head_entries = repo
        .commit_entries(&repo.head_commit().context("Found no head commit..")?)
        .context("Found no commit entries..")?;

    let staged_untracked_diff: Vec<_> = git::diff(&staged_entries, &untracked_entries).collect();
    let head_staged_diff: Vec<_> = git::diff(&head_entries, &staged_entries).collect();

    if head_staged_diff.is_empty() && staged_untracked_diff.is_empty() {
        println!("No changes..");
        return Ok(());
    }

    let mut matcher = PatternListMatcher::new(PathBuf::from(&global_opts.parser_path));

    if !global_opts.no_core_patterns {
        let load_pattern_results = matcher
            .load_core_patterns()
            .context("Failed to load core patterns")?;

        crate::cli::pattern::print_load_pattern_results(load_pattern_results);
    }

    if let Some(patterns_path) = &global_opts.patterns_path {
        let load_pattern_results = matcher
            .load_patterns(patterns_path)
            .context(format!("Failed to load patterns from {}", patterns_path))?;

        crate::cli::pattern::print_load_pattern_results(load_pattern_results);
    }

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
                match matcher.pattern_for_file_path(path) {
                    Some(pattern) => {
                        let lhs = pattern.matches(before_content, None, None);
                        let rhs = pattern.matches(after_content, None, None);

                        let (lhs, rhs) = match (lhs, rhs) {
                            (Ok(lhs), Ok(rhs)) => (lhs, rhs),
                            _ => {
                                println!(
                                    "{} {} {}",
                                    "~".purple(),
                                    path.green(),
                                    "Failed to pattern match".red()
                                );
                                continue;
                            }
                        };

                        println!("{} {}", "~".purple(), path.green());
                        let (novel_lhs, novel_rhs) = diff::diff(before_content, after_content);
                        let mut changes = diff_matches(
                            before_content,
                            after_content,
                            novel_lhs,
                            novel_rhs,
                            lhs,
                            rhs,
                        );

                        changes.sort_by_key(|diff| match diff {
                            PatternMatchDiff::Added(mtch) => mtch.range_first_byte(),
                            PatternMatchDiff::Deleted(mtch) => mtch.range_first_byte(),
                            PatternMatchDiff::Modified { before, .. } => before.range_first_byte(),
                        });

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
                match matcher.pattern_for_file_path(path) {
                    Some(pattern) => {
                        let lhs = pattern.matches(before_content, None, None);
                        let rhs = pattern.matches(after_content, None, None);

                        let (lhs, rhs) = match (lhs, rhs) {
                            (Ok(lhs), Ok(rhs)) => (lhs, rhs),
                            _ => {
                                println!(
                                    "{} {} {}",
                                    "~".purple(),
                                    path.green(),
                                    "Failed to pattern match".red()
                                );
                                continue;
                            }
                        };

                        println!("{} {}", "~".purple(), path.green());
                        let (novel_lhs, novel_rhs) = diff::diff(before_content, after_content);

                        let changes = diff_matches(
                            before_content,
                            after_content,
                            novel_lhs,
                            novel_rhs,
                            lhs,
                            rhs,
                        );

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
    #[allow(dead_code)]
    Modified {
        before: Rc<PatternMatch>,
        after: Rc<PatternMatch>,
    },
}

fn diff_matches(
    before_content: &[u8],
    after_content: &[u8],
    novel_lhs: Vec<u32>,
    novel_rhs: Vec<u32>,
    mut lhs: Vec<Rc<PatternMatch>>,
    mut rhs: Vec<Rc<PatternMatch>>,
) -> Vec<PatternMatchDiff> {
    #[derive(Debug)]
    struct PatternMatchWithHash(Rc<PatternMatch>);
    // Retrns wrong symols
    impl std::hash::Hash for PatternMatchWithHash {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.0.kind.hash(state);
            self.0.full_qualifiers.hash(state);
        }
    }
    impl PartialEq for PatternMatchWithHash {
        fn eq(&self, other: &Self) -> bool {
            self.0.kind == other.0.kind && self.0.full_qualifiers == other.0.full_qualifiers
        }
    }
    impl Eq for PatternMatchWithHash {}

    // Too avoid a marking a match as changed when the change in entirely located in a sub match
    lhs.sort_by_key(|mtch| mtch.range_byte_count());
    rhs.sort_by_key(|mtch| mtch.range_byte_count());

    let mut lhs_changed = HashSet::new();
    for line in novel_lhs {
        // TODO: Change so all of rhs is not iterated through
        // TODO: Make it possible for changes to be applied to all parents aswell. Some flag should
        // be used
        let mut change_is_contained_in_one_liner = false;
        let mut change_is_contained = false;
        for mtch in lhs.extract_if(|mtch| {
            if !change_is_contained && mtch.contains_line(line as usize) {
                let mtch_is_one_liner = mtch.is_one_liner();
                match (change_is_contained_in_one_liner, mtch_is_one_liner) {
                    (true, true) => true,
                    (false, true) => {
                        change_is_contained_in_one_liner = true;
                        true
                    }
                    (false, false) => {
                        change_is_contained = true;
                        true
                    }
                    (true, false) => {
                        change_is_contained = true;
                        false
                    }
                }
            } else {
                false
            }
        }) {
            lhs_changed.insert(PatternMatchWithHash(mtch));
        }
    }
    let mut lhs_unchanged: HashSet<_> =
        HashSet::from_iter(lhs.into_iter().map(PatternMatchWithHash));

    // Can be done in a single pass..
    let mut rhs_changed = HashSet::new();
    for line in novel_rhs {
        // TODO: Change so all of rhs is not iterated through
        let mut change_is_contained_in_one_liner = false;
        let mut change_is_contained = false;
        for mtch in rhs.extract_if(|mtch| {
            if !change_is_contained && mtch.contains_line(line as usize) {
                let mtch_is_one_liner = mtch.is_one_liner();
                match (change_is_contained_in_one_liner, mtch_is_one_liner) {
                    (true, true) => true,
                    (false, true) => {
                        change_is_contained_in_one_liner = true;
                        true
                    }
                    (false, false) => {
                        change_is_contained = true;
                        true
                    }
                    (true, false) => {
                        change_is_contained = true;
                        false
                    }
                }
            } else {
                false
            }
        }) {
            rhs_changed.insert(PatternMatchWithHash(mtch));
        }
    }
    let mut rhs_unchanged: HashSet<_> =
        HashSet::from_iter(rhs.into_iter().map(PatternMatchWithHash));

    let mut diff = vec![];

    let modified = lhs_changed
        .extract_if(|lhs_mtch| rhs_changed.contains(lhs_mtch))
        .collect::<Vec<_>>()
        .into_iter()
        .filter_map(|lhs_mtch| {
            rhs_changed
                .take(&lhs_mtch)
                .filter(|rhs_mtch| {
                    lhs_mtch.0.checksum(before_content) != rhs_mtch.0.checksum(after_content)
                })
                .map(|rhs_mtch| PatternMatchDiff::Modified {
                    before: lhs_mtch.0,
                    after: rhs_mtch.0,
                })
        });
    diff.extend(modified);

    let deleted_or_modified =
        lhs_changed
            .into_iter()
            .map(|lhs_mtch| match rhs_unchanged.take(&lhs_mtch) {
                Some(rhs_mtch) => PatternMatchDiff::Modified {
                    before: lhs_mtch.0,
                    after: rhs_mtch.0,
                },
                None => PatternMatchDiff::Deleted(lhs_mtch.0),
            });
    diff.extend(deleted_or_modified);

    let added_or_modified =
        rhs_changed
            .into_iter()
            .map(|rhs_mtch| match lhs_unchanged.take(&rhs_mtch) {
                Some(lhs_mtch) => PatternMatchDiff::Modified {
                    before: lhs_mtch.0,
                    after: rhs_mtch.0,
                },
                None => PatternMatchDiff::Added(rhs_mtch.0),
            });
    diff.extend(added_or_modified);

    diff
}
