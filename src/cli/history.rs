use crate::cli::command::{
    BuildHistoryArgs, GlobalOpts, History, HistoryCommitsArgs, HistoryOpts, HistorySubcommands,
    InspectHistoryArgs,
};
use crate::datastore;
use crate::diff;
use crate::git;
use crate::parser::PatternListMatcher;
use anyhow::{Context, Ok};
use colored::Colorize;
use git::{ChangeHistoryIterator, CommitExt, RepositoryExt};
use itertools::Itertools;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

fn id_to_hex(id: &[u8]) -> String {
    let mut s = String::with_capacity(id.len() * 2);
    for byte in id {
        s += format!("{:02x}", byte).as_str();
    }
    s
}

pub(crate) fn handle_history_subcommand(
    command: &History,
    global_opts: &GlobalOpts,
) -> anyhow::Result<()> {
    match &command.subcommand {
        HistorySubcommands::Inspect(args) => inspect_histry(args, &command.opts, global_opts),
        HistorySubcommands::Commits(args) => list_commits(args, &command.opts, global_opts),
        HistorySubcommands::Build(args) => build_history(args, &command.opts, global_opts),
        HistorySubcommands::Changes => list_changes(&command.opts, global_opts),
    }
}

fn list_changes(history_opts: &HistoryOpts, _global_opts: &GlobalOpts) -> anyhow::Result<()> {
    let datastore = datastore::open(&history_opts.datastore_path)?;

    let changes = datastore::query_changes(&datastore)?;

    for change in changes {
        println!(
            "{} {} {} {} {} (+{} -{}) -> {}",
            change.symbol.kind.bright_blue(),
            change.symbol.qualifiers.bright_yellow(),
            change.symbol.file_path.bright_black(),
            id_to_hex(&change.commit.id).bright_blue(),
            change.commit.seconds_since_epoch.to_string().bright_black(),
            change.novel_rhs.to_string().green(),
            change.novel_lhs.to_string().red(),
            change.size_after
        );
    }

    Ok(())
}

fn list_git_commits(args: &HistoryCommitsArgs, _global_opts: &GlobalOpts) -> anyhow::Result<()> {
    fn without_trailing_newline(mut string: String) -> String {
        if string.ends_with('\n') {
            string.pop();
            if string.ends_with('\r') {
                string.pop();
            }
        }
        string
    }
    let mut repo = git::open(args.repo.as_str()).context("Failed to get git repository")?;

    repo.object_cache_size(Some(args.cache_size.as_u64() as usize));

    let mut commit = repo.head_commit().context("Failed to get head commit")?;

    loop {
        let hash = commit.id().to_hex().to_string();
        let time_format = time::macros::format_description!("[day].[month].[year]");
        let time = commit.decode()?.author.time.format(time_format);
        let message = commit.message()?;
        println!(
            "{} {} {}",
            hash.bright_black(),
            time.bright_blue(),
            without_trailing_newline(message.title.to_string())
        );

        let Some(parent) = commit.parent() else { break };

        commit = parent;
    }

    Ok(())
}

fn list_datastore_commits(
    _args: &HistoryCommitsArgs,
    history_opts: &HistoryOpts,
    _global_opts: &GlobalOpts,
) -> anyhow::Result<()> {
    let datastore = datastore::open(&history_opts.datastore_path)?;

    for commit in datastore::all_commits(&datastore)? {
        let hash = id_to_hex(&commit.id);
        let time = commit.seconds_since_epoch.to_string();

        println!("{} {}", hash.bright_black(), time.bright_blue());
    }

    Ok(())
}

fn list_commits(
    args: &HistoryCommitsArgs,
    history_opts: &HistoryOpts,
    global_opts: &GlobalOpts,
) -> anyhow::Result<()> {
    match args.location {
        crate::cli::command::CommitLocation::Git => list_git_commits(args, global_opts),
        crate::cli::command::CommitLocation::Datastore => {
            list_datastore_commits(args, history_opts, global_opts)
        }
    }
}

fn inspect_histry(
    args: &InspectHistoryArgs,
    history_opts: &HistoryOpts,
    _global_opts: &GlobalOpts,
) -> anyhow::Result<()> {
    let datastore = datastore::open(&history_opts.datastore_path)?;

    let symbol = datastore::Symbol {
        kind: args.kind.clone(),
        file_path: args.file.clone(),
        qualifiers: args.qualifiers.clone(),
    };

    // let mut changes = datastore::changes_for_symbol(&datastore, &symbol)?;
    let changes = datastore::query_changes(&datastore)?;

    let all_commits = changes
        .iter()
        .map(|change| change.commit.clone())
        .unique()
        .collect_vec();

    let mut symbol_changes = changes
        .iter()
        .filter(|change| change.symbol == symbol)
        .collect_vec();

    symbol_changes.sort_by_key(|change| std::cmp::Reverse(change.commit.seconds_since_epoch));

    let Some(first_symbol_change) = symbol_changes.first() else {
        println!("Found no commits for symbol..");
        return Ok(());
    };

    let percentage_of_total = symbol_changes.len() as f32 / all_commits.len() as f32;

    let symbol_introduction = all_commits
        .iter()
        .position(|commit| commit == &first_symbol_change.commit)
        .unwrap_or(0);

    let percentage_of_total_since_introduction =
        symbol_changes.len() as f32 / (all_commits.len() - symbol_introduction) as f32;

    println!(
        "{} {} in {} has changes in {} commits, {:.2}% of total commits, {:.2}% of commits since introduction",
        symbol.kind.bright_blue(),
        symbol.qualifiers.bright_yellow(),
        symbol.file_path.bright_black(),
        symbol_changes.len(),
        percentage_of_total * 100.0,
        percentage_of_total_since_introduction * 100.0,
    );
    for change in symbol_changes.iter() {
        let hash = id_to_hex(&change.commit.id);
        let time = change.commit.seconds_since_epoch.to_string();

        println!(
            "- {} {}, (-{}, +{}) -> {}",
            hash.bright_black(),
            time.bright_blue(),
            change.novel_lhs.to_string().red(),
            change.novel_rhs.to_string().green(),
            change.size_after
        );
    }

    let mut other_symbols = HashMap::new();

    for change in changes.iter() {
        if change.symbol != symbol
            && symbol_changes
                .iter()
                .any(|other| other.commit == change.commit)
        {
            *other_symbols.entry(change.symbol.clone()).or_insert(0) += 1;
        }
    }

    let mut other_symbols = other_symbols.into_iter().collect_vec();
    other_symbols.sort_by_key(|(_, v)| std::cmp::Reverse(*v));

    println!();
    println!("Frequently changed together with: ");
    for (symbol, count) in other_symbols
        .into_iter()
        .filter(|(symbol, _)| symbol.kind != "file")
        .take(10)
    {
        let percentage_change_togheter = count as f32 / symbol_changes.len() as f32;
        println!(
            "- {} {} {}, {:.2}%",
            symbol.kind.bright_blue(),
            symbol.qualifiers.bright_yellow(),
            symbol.file_path.bright_black(),
            percentage_change_togheter * 100.0
        );
    }

    Ok(())
}

fn build_history(
    args: &BuildHistoryArgs,
    history_opts: &HistoryOpts,
    global_opts: &GlobalOpts,
) -> anyhow::Result<()> {
    let mut datastore = datastore::open(&history_opts.datastore_path)?;
    let mut repo = git::open(&args.repo)?;

    repo.object_cache_size(Some(args.cache_size.as_u64() as usize));

    if args.rebuild {
        datastore::purge(&datastore)?;
        log::info!(
            "Sucessfully cleared existing history: {}",
            history_opts.datastore_path
        );
    }

    let earliest_parsed_commit = datastore::earliest_commit(&datastore)?;
    let latest_parsed_commit = datastore::latest_commit(&datastore)?;

    if let Some(ref latest_parsed_commit) = latest_parsed_commit {
        log::info!(
            "Latest parsed commit: {}",
            id_to_hex(&latest_parsed_commit.id)
        );
    }
    if let Some(ref earliest_parsed_commit) = earliest_parsed_commit {
        log::info!(
            "Earliest parsed commit: {}",
            id_to_hex(&earliest_parsed_commit.id)
        );
    }

    let head_commit = repo.head_commit()?;

    let changes = repo
        .changes_in_history(head_commit)
        .take_while(|(commit, _)| {
            Some(commit.id.as_slice())
                != latest_parsed_commit
                    .as_ref()
                    .map(|commit| commit.id.as_slice())
        });

    let earliest_parsed_commit_parent = earliest_parsed_commit.map(|commit| {
        let commit_object = repo.find_object(commit.id.as_slice()).ok()?.into_commit();
        commit_object.parent()
    });

    let additional_changes = match earliest_parsed_commit_parent {
        Some(Some(parent)) => repo.changes_in_history(parent),
        _ => ChangeHistoryIterator::new_empty(&repo),
    };

    let changes = changes.chain(additional_changes);

    let mut matcher = PatternListMatcher::new(PathBuf::from(&global_opts.parser_path));

    crate::cli::pattern::load_patterns_from_opts(&mut matcher, global_opts)?;

    #[derive(Debug, PartialEq, Eq, Hash)]
    struct TreeCacheKey {
        object: String,
        // Not really needed as of now but maybe needed in the future if support for multiple
        // matching patterns exist
        pattern_hash: u32,
    }
    let mut total_duration = std::time::Duration::ZERO;
    // TODO: Also add matches as part of cache value
    let mut tree_cache: HashMap<TreeCacheKey, _> = HashMap::new();
    let mut all_changes = vec![];

    for (gix_commit, changes) in changes {
        let t = std::time::Instant::now();
        let commit = datastore::Commit {
            id: gix_commit.id.as_slice().to_vec(),
            seconds_since_epoch: gix_commit.decode()?.author.time.seconds,
        };

        for change in changes {
            match change.event {
                git::Event::Addition { id, .. } => {
                    if let Some(pattern) =
                        matcher.pattern_for_file_path(&change.location.to_string())
                    {
                        let data = &id.object().context("Failed to get git object data")?.data;
                        let key = TreeCacheKey {
                            object: id.to_hex().to_string(),
                            pattern_hash: pattern.hash,
                        };
                        let tree = tree_cache.remove(&key);

                        let tree = match tree {
                            Some(tree) => tree,
                            None => pattern.parse(data, None)?,
                        };

                        // Insert change for entire file
                        let root_range = tree.root_node().range();
                        all_changes.push(datastore::Change {
                            commit: commit.clone(),
                            symbol: datastore::Symbol {
                                qualifiers: "".into(),
                                kind: "file".into(),
                                file_path: change.location.to_string(),
                            },
                            novel_lhs: 0,
                            novel_rhs: root_range.end_point.row as u32,
                            size_after: root_range.end_point.row as u64,
                        });

                        let matches = pattern
                            .matches(data, Some(&tree), None)
                            .context("Failed to get pattern matches")?;

                        all_changes.extend(matches.into_iter().map(|mtch| {
                            datastore::Change {
                                commit: commit.clone(),
                                symbol: datastore::Symbol {
                                    kind: mtch.kind.to_string(),
                                    file_path: change.location.to_string(),
                                    qualifiers: mtch
                                        .full_qualifiers
                                        .join(&pattern.qualifier_settings.seperator),
                                },
                                novel_lhs: 0,
                                novel_rhs: mtch.range_line_count() as u32,
                                size_after: mtch.range_line_count() as u64, // pattern_hash: Some(pattern.hash),
                            }
                        }));
                    }
                }
                git::Event::Deletion { id, .. } => {
                    if let Some(pattern) =
                        matcher.pattern_for_file_path(&change.location.to_string())
                    {
                        let data = &id.object().context("Failed to get git object data")?.data;
                        let tree = pattern
                            .parse(data, None)
                            .context("Failed to parse git object data to a tree")?;

                        // Insert change for entire file
                        all_changes.push(datastore::Change {
                            commit: commit.clone(),
                            symbol: datastore::Symbol {
                                qualifiers: "".into(),
                                kind: "file".into(),
                                file_path: change.location.to_string(),
                            },
                            novel_lhs: tree.root_node().range().end_point.row as u32,
                            novel_rhs: 0,
                            size_after: 0,
                        });

                        let matches = pattern
                            .matches(data, Some(&tree), None)
                            .context("Failed to get matches")?;
                        let key = TreeCacheKey {
                            object: id.to_hex().to_string(),
                            pattern_hash: pattern.hash,
                        };
                        tree_cache.insert(key, tree);

                        all_changes.extend(matches.into_iter().map(|mtch| {
                            datastore::Change {
                                commit: commit.clone(),
                                symbol: datastore::Symbol {
                                    kind: mtch.kind.to_string(),
                                    file_path: change.location.to_string(),
                                    qualifiers: mtch
                                        .full_qualifiers
                                        .join(&pattern.qualifier_settings.seperator),
                                },
                                novel_lhs: mtch.range_line_count() as u32,
                                novel_rhs: 0,
                                size_after: 0, // pattern_hash: Some(pattern.hash),
                            }
                        }));
                    }
                }
                git::Event::Modification {
                    previous_id, id, ..
                } => {
                    if let Some(pattern) =
                        matcher.pattern_for_file_path(&change.location.to_string())
                    {
                        let lhs_content = &previous_id.object()?.data;
                        let rhs_content = &id.object()?.data;
                        let (novel_lhs, novel_rhs) = diff::diff(lhs_content, rhs_content);

                        let key = TreeCacheKey {
                            object: id.to_hex().to_string(),
                            pattern_hash: pattern.hash,
                        };
                        let mut tree = tree_cache
                            .remove(&key)
                            .or_else(|| pattern.parse(rhs_content, None).ok())
                            .context("Failed to get tree-sitter tree")?;

                        let rhs = pattern.matches(rhs_content, Some(&tree), None)?;

                        let after_size = tree.root_node().range().end_point.row;

                        let changes = diff::changes(rhs_content, lhs_content);
                        for change in changes {
                            tree.edit(&change);
                        }

                        let tree = pattern
                            .parse(lhs_content, Some(&tree))
                            .context("Failed to parse git object data into a tree")?;

                        // Insert change for entire file
                        all_changes.push(datastore::Change {
                            commit: commit.clone(),
                            symbol: datastore::Symbol {
                                qualifiers: "".into(),
                                kind: "file".into(),
                                file_path: change.location.to_string(),
                            },
                            novel_lhs: novel_lhs.len() as u32,
                            novel_rhs: novel_rhs.len() as u32,
                            size_after: after_size as u64,
                        });

                        let lhs = pattern.matches(lhs_content, Some(&tree), None)?;
                        let key = TreeCacheKey {
                            object: previous_id.to_hex().to_string(),
                            pattern_hash: pattern.hash,
                        };
                        tree_cache.insert(key, tree);

                        let qualifiers: HashSet<_> = lhs
                            .iter()
                            .map(|mtch| &mtch.full_qualifiers)
                            .chain(rhs.iter().map(|mtch| &mtch.full_qualifiers))
                            .cloned()
                            .collect();
                        all_changes.extend(qualifiers.into_iter().filter_map(|full_qualifiers| {
                            let lhs = lhs
                                .iter()
                                .find(|mtch| mtch.full_qualifiers == full_qualifiers);
                            let rhs = rhs
                                .iter()
                                .find(|mtch| mtch.full_qualifiers == full_qualifiers);

                            match (lhs, rhs) {
                                (Some(lhs), None) => Some(datastore::Change {
                                    commit: commit.clone(),
                                    symbol: datastore::Symbol {
                                        file_path: change.location.to_string(),
                                        kind: lhs.kind.to_string(),
                                        qualifiers: lhs
                                            .full_qualifiers
                                            .join(&pattern.qualifier_settings.seperator),
                                    },
                                    novel_lhs: lhs.range_line_count() as u32,
                                    novel_rhs: 0,
                                    size_after: 0,
                                }),
                                (None, Some(rhs)) => Some(datastore::Change {
                                    commit: commit.clone(),
                                    symbol: datastore::Symbol {
                                        file_path: change.location.to_string(),
                                        kind: rhs.kind.to_string(),
                                        qualifiers: rhs
                                            .full_qualifiers
                                            .join(&pattern.qualifier_settings.seperator),
                                    },
                                    novel_lhs: 0,
                                    novel_rhs: rhs.range_line_count() as u32,
                                    size_after: rhs.range_line_count() as u64,
                                }),
                                (Some(lhs), Some(rhs)) => {
                                    if lhs.checksum(lhs_content) == rhs.checksum(rhs_content) {
                                        None
                                    } else {
                                        Some(datastore::Change {
                                            commit: commit.clone(),
                                            symbol: datastore::Symbol {
                                                file_path: change.location.to_string(),
                                                kind: rhs.kind.to_string(),
                                                qualifiers: rhs
                                                    .full_qualifiers
                                                    .join(&pattern.qualifier_settings.seperator),
                                            },
                                            novel_lhs: novel_lhs
                                                .iter()
                                                .map(|&line| line as usize)
                                                .filter(|&line| lhs.contains_line(line))
                                                .count()
                                                as u32,
                                            novel_rhs: novel_rhs
                                                .iter()
                                                .map(|&line| line as usize)
                                                .filter(|&line| rhs.contains_line(line))
                                                .count()
                                                as u32,
                                            size_after: rhs.range_line_count() as u64,
                                        })
                                    }
                                }
                                (None, None) => unreachable!(),
                            }
                        }));
                    }
                }
            }
        }
        log::info!(
            "Parsed commit {}, currently cached {} trees, {:?} elapsed",
            gix_commit.id.to_hex(),
            tree_cache.len(),
            t.elapsed()
        );
        total_duration += t.elapsed();
    }

    let len = all_changes.len();
    let t = std::time::Instant::now();
    datastore::insert_changes(&mut datastore, all_changes.into_iter())?;
    total_duration += t.elapsed();
    println!("Finished building history, {len} changes, {total_duration:?} elapsed",);

    Ok(())
}
