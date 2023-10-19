use crate::cli::command::{
    BuildHistoryArgs, GlobalOpts, History, HistoryOpts, HistorySubcommands,
    InspectHistoryArgs,
};
use crate::datastore;
use crate::diff;
use crate::git;
use crate::parser::PatternListMatcher;
use anyhow::{Context, Ok};
use colored::Colorize;
use git::{ChangeHistoryIterator, CommitExt, RepositoryExt};
use gix::Repository;
use itertools::Itertools;
use rusqlite::Connection;
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
        HistorySubcommands::Inspect(args) => inspect_history(args, &command.opts, global_opts),
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

pub(crate) fn assert_history_updated(repository: &Repository, datastore: &Connection, allow_outdated: bool, allow_detached: bool) -> anyhow::Result<()> {
    let head = repository.head()?;

    if !allow_detached && head.is_detached() {
        anyhow::bail!("HEAD is deatached and results will be wrong")
    }

    if !allow_outdated {
        let anyhow::Result::Ok(Some(commit)) = datastore::latest_commit(datastore) else {
            anyhow::bail!("History has not been built. Run 'intelligit history build'");
        };
        if commit.id.as_slice() != head.id().context("Failed to get id from head commit")?.as_bytes() {
            anyhow::bail!("History is not updated. Run 'intelligit history build'");
        }
    }

    Ok(())
}



fn inspect_history(
    args: &InspectHistoryArgs,
    history_opts: &HistoryOpts,
    _global_opts: &GlobalOpts,
) -> anyhow::Result<()> {
    if let (None, None, None) = (&args.file, &args.kind, &args.qualifiers) {
        anyhow::bail!("file, kind or qualifier must be set.");
    }

    let datastore = datastore::open(&history_opts.datastore_path)?;

    let symbols = datastore::query_symbols(
        &datastore,
        args.file.as_deref(),
        args.kind.as_deref(),
        args.qualifiers.as_deref(),
    )?;

    let symbol = match &symbols[..] {
        [symbol] => symbol.clone(),
        [] => {
            println!("Found no symbols..");
            return Ok(());
        },
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

    let changes = datastore::query_changes(&datastore)?;

    let mut all_commits = changes
        .iter()
        .map(|change| change.commit.clone())
        .unique()
        .collect_vec();

    let mut symbol_changes = changes
        .iter()
        .filter(|change| change.symbol == symbol)
        .collect_vec();

    symbol_changes.sort_by_key(|change| change.commit.seconds_since_epoch);
    all_commits.sort_by_key(|commit| commit.seconds_since_epoch);

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

                        // We calculate diff two times. This is probably not necessary
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
