#![feature(hash_extract_if)]
#![feature(extract_if)]
use std::{collections::HashSet, path::PathBuf};

use colored::Colorize;
use git::RepositoryExt;
use tree_sitter::{CreateTSPatternListError, TSPatternListMatcher, TSPatternMatch};

use anyhow::Context;
use clap::{Args, ColorChoice, Parser};

#[derive(Debug, Parser)]
pub struct App {
    #[clap(flatten)]
    global_opts: GlobalOpts,

    #[clap(subcommand)]
    subcommand: Subcommands,
}

#[derive(Debug, Args)]
struct GlobalOpts {
    #[clap(long, global = true, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,
    /// Directory to look for and store parsers
    #[clap(long = "parsers", global = true, default_value = ".intelligit")]
    parser_path: String,

    /// Directory to look for patterns
    #[clap(long = "patterns", global = true, default_value = "./patterns")]
    patterns_path: String,

    /// Commands will output lots of information that might be useful
    #[clap(long = "verbose", global = true, default_value_t = false)]
    verbose: bool,
}

#[derive(Debug, clap::Subcommand)]
pub enum Subcommands {
    /// Show staged and untracked changes
    Status { repo: Option<String> },
    /// Display all symbols for a file or directory
    Symbols {
        #[clap(default_value = "./")]
        path: String,
        /// Show tags instead of kind
        #[clap(long, short = 't', default_value_t = false)]
        tags: bool,
    },
    /// For parser specific commands
    #[clap(subcommand)]
    Parser(ParserSubcommands),

    /// For pattern specific commands
    #[clap(subcommand)]
    Pattern(PatternSubcommands),
}

#[derive(Debug, clap::Subcommand)]
pub enum ParserSubcommands {
    /// List all installed parsers
    List,
}

#[derive(Debug, clap::Subcommand)]
pub enum PatternSubcommands {
    /// List all patterns
    List,
    /// Verify patterns
    Verify,
}

fn print_status(root: String, global_opts: &GlobalOpts) -> anyhow::Result<()> {
    let t = std::time::Instant::now();
    let repo = git::open(root.as_str()).unwrap();

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

    let mut matcher = TSPatternListMatcher::new(PathBuf::from(&global_opts.parser_path));

    let load_pattern_results =
        matcher
            .load_patterns(&global_opts.patterns_path)
            .context(format!(
                "Failed to load patterns from {}",
                &global_opts.patterns_path
            ))?;

    if global_opts.verbose {
        print_load_pattern_results(load_pattern_results);
    }

    if !head_staged_diff.is_empty() {
        println!("Staged:");

        for file in head_staged_diff.iter() {
            if let git::DiffResult::Added { path, content } = file {
                match matcher.pattern_for_file_path(path) {
                    Some(pattern) => {
                        let matches = match pattern.matches(&content) {
                            Ok(matches) => matches,
                            Err(e) => {
                                println!(
                                    "{} {} ({} {})",
                                    "+".green(),
                                    path.green(),
                                    "Pattern matching failed...".bright_black(),
                                    e.to_string()
                                );
                                continue;
                            }
                        };
                        println!("{} {}", "+".green(), path.green(),);

                        for mtch in matches {
                            println!(
                                "  + {} {}",
                                mtch.kind.bright_blue(),
                                mtch.qualifiers
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
        for file in head_staged_diff.iter() {
            if let git::DiffResult::Deleted { path, .. } = file {
                println!("{} {}", "-".red(), path.green());
            }
        }
        for file in head_staged_diff.iter() {
            if let git::DiffResult::Modified {
                path,
                before_content,
                after_content,
            } = file
            {
                match matcher.pattern_for_file_path(path) {
                    Some(pattern) => {
                        let lhs = pattern.matches(&before_content);
                        let rhs = pattern.matches(&after_content);

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
                        let (novel_lhs, novel_rhs) = diff::diff(&before_content, &after_content);
                        let mut changes = diff_matches(
                            &before_content,
                            &after_content,
                            novel_lhs,
                            novel_rhs,
                            lhs,
                            rhs,
                        );

                        changes.sort_by_key(|diff| match diff {
                            TSPatternMatchDiff::Added(mtch) => mtch.range.start_byte,
                            TSPatternMatchDiff::Deleted(mtch) => mtch.range.start_byte,
                            TSPatternMatchDiff::Modified { before, .. } => before.range.start_byte,
                        });

                        for change in changes {
                            match change {
                                TSPatternMatchDiff::Added(mtch) => println!(
                                    "  + {} {}",
                                    mtch.kind.bright_blue(),
                                    mtch.qualifiers
                                        .join(&pattern.qualifier_settings.seperator)
                                        .bright_green()
                                ),
                                TSPatternMatchDiff::Deleted(mtch) => println!(
                                    "  - {} {}",
                                    mtch.kind.bright_blue(),
                                    mtch.qualifiers
                                        .join(&pattern.qualifier_settings.seperator)
                                        .bright_red()
                                ),
                                TSPatternMatchDiff::Modified { before, .. } => println!(
                                    "  ~ {} {}",
                                    before.kind.bright_blue(),
                                    before
                                        .qualifiers
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

        for file in staged_untracked_diff.iter() {
            if let git::DiffResult::Added { path, .. } = file {
                println!("{} {}", "+".green(), path.bright_blue());
            }
        }
        for file in staged_untracked_diff.iter() {
            if let git::DiffResult::Deleted { path, .. } = file {
                println!("{} {}", "-".red(), path.bright_blue());
            }
        }
        for file in staged_untracked_diff.iter() {
            if let git::DiffResult::Modified {
                path,
                before_content,
                after_content,
            } = file
            {
                match matcher.pattern_for_file_path(path) {
                    Some(pattern) => {
                        let lhs = pattern.matches(&before_content);
                        let rhs = pattern.matches(&after_content);

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
                        let (novel_lhs, novel_rhs) = diff::diff(&before_content, &after_content);
                        let changes = diff_matches(
                            &before_content,
                            &after_content,
                            novel_lhs,
                            novel_rhs,
                            lhs,
                            rhs,
                        );

                        for change in changes {
                            match change {
                                TSPatternMatchDiff::Added(mtch) => println!(
                                    "  + {} {}",
                                    mtch.kind.bright_blue(),
                                    mtch.qualifiers
                                        .join(&pattern.qualifier_settings.seperator)
                                        .bright_green()
                                ),
                                TSPatternMatchDiff::Deleted(mtch) => println!(
                                    "  - {} {}",
                                    mtch.kind.bright_blue(),
                                    mtch.qualifiers
                                        .join(&pattern.qualifier_settings.seperator)
                                        .bright_red()
                                ),
                                TSPatternMatchDiff::Modified { before, .. } => println!(
                                    "  ~ {} {}",
                                    before.kind.bright_blue(),
                                    before
                                        .qualifiers
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
    println!("{}", format!("{:?} elapsed", t.elapsed()).bright_black());

    Ok(())
}

fn print_symbols(path: &str, show_tags: bool, global_opts: &GlobalOpts) -> anyhow::Result<()> {
    let metadata = std::fs::metadata(path).context(format!("Did not find {}", path))?;

    let files = if metadata.is_file() {
        vec![path.to_owned()]
    } else {
        let mut builder = ignore::WalkBuilder::new(path);
        builder.hidden(false);

        builder
            .build()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().map(|ft| ft.is_file()).unwrap_or(false))
            .filter_map(|entry| {
                let entry_path = entry.path();

                if entry_path.starts_with(format!("{path}/.git")) {
                    None
                } else {
                    entry_path.to_str().map(|s| s.to_owned())
                }
            })
            .collect()
    };

    let mut matcher = TSPatternListMatcher::new(PathBuf::from(&global_opts.parser_path));

    let results = matcher
        .load_patterns(&global_opts.patterns_path)
        .ok()
        .context("Found no patterns..")?;

    if false {
        print_load_pattern_results(results);
    }

    for file in files {
        let pattern = match matcher.pattern_for_file_path(&file) {
            Some(pattern) => pattern,
            None => continue,
        };

        println!("{}", file.bright_black());

        let data = std::fs::read(&file).context(format!("Failed to read content from {}", file))?;

        let matches = pattern.matches(&data)?;

        if show_tags {
            for mtch in matches {
                if let Some(tag) = mtch.tag {
                    println!(
                        "{} {} ({}-{})",
                        tag.bright_blue(),
                        mtch.qualifiers
                            .join(&pattern.qualifier_settings.seperator)
                            .white(),
                        mtch.range.start_point.row + 1,
                        mtch.range.end_point.row + 1,
                    );
                }
            }
        } else {
            for mtch in matches {
                println!(
                    "{} {} ({}-{})",
                    mtch.kind.bright_blue(),
                    mtch.qualifiers
                        .join(&pattern.qualifier_settings.seperator)
                        .white(),
                    mtch.range.start_point.row + 1,
                    mtch.range.end_point.row + 1,
                );
            }
        }
    }

    Ok(())
}

fn list_patterns(global_opts: &GlobalOpts) -> anyhow::Result<()> {
    let mut matcher = TSPatternListMatcher::new(PathBuf::from(&global_opts.parser_path));

    let res = matcher.load_patterns(&global_opts.patterns_path).unwrap();

    if global_opts.verbose {
        print_load_pattern_results(res);
    }

    let indent = "  ";
    for pattern in matcher.patterns {
        println!("{}", format!("{}", pattern.path.display()).bright_black());
        println!(
            "{}parser: {}",
            indent,
            format!("{:?}", pattern.parser).bright_black()
        );
        println!(
            "{}{} symbol patterns",
            indent,
            format!("{:?}", pattern.patterns.len()).bright_blue()
        );
    }

    Ok(())
}

fn print_load_pattern_results(
    load_pattern_result: Vec<(PathBuf, Result<(), CreateTSPatternListError>)>,
) {
    for (path, res) in load_pattern_result {
        match res {
            Ok(_) => println!(
                "{}",
                format!("{} loaded successfully", path.display()).bright_black()
            ),
            Err(err) => {
                println!(
                    "{}",
                    format!("{} loaded unsuccessfully", path.display()).bright_black()
                );
                println!("{}", format!("{}", err.to_string()).red());
            }
        }
    }
}

fn verify_patterns(global_opts: &GlobalOpts) -> anyhow::Result<()> {
    let parser_path = PathBuf::from(&global_opts.parser_path);
    let mut matcher = TSPatternListMatcher::new(parser_path);

    let results = matcher
        .load_patterns(&global_opts.patterns_path)
        .context("Failed to get patterns")?;

    if global_opts.verbose {
        print_load_pattern_results(results);
    }

    if matcher.patterns.is_empty() {
        println!("Found no patterns to verify..");
    } else {
        for pattern in matcher.patterns {
            match pattern.verify() {
                Ok(_) => println!("{}", format!("{}", pattern.path.display()).bright_green()),
                Err(error) => {
                    println!("{}", format!("{}", pattern.path.display()).bright_red());

                    println!("  - {}", error.to_string());
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
enum TSPatternMatchDiff {
    Added(TSPatternMatch),
    Deleted(TSPatternMatch),
    #[allow(dead_code)]
    Modified {
        before: TSPatternMatch,
        after: TSPatternMatch,
    },
}

fn diff_matches(
    before_content: &[u8],
    after_content: &[u8],
    novel_lhs: Vec<u32>,
    novel_rhs: Vec<u32>,
    mut lhs: Vec<TSPatternMatch>,
    mut rhs: Vec<TSPatternMatch>,
) -> Vec<TSPatternMatchDiff> {
    #[derive(Debug)]
    struct TSPatternMatchWithHash(TSPatternMatch);
    impl std::hash::Hash for TSPatternMatchWithHash {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.0.kind.hash(state);
            self.0.qualifiers.hash(state);
        }
    }
    impl PartialEq for TSPatternMatchWithHash {
        fn eq(&self, other: &Self) -> bool {
            self.0.kind == other.0.kind && self.0.qualifiers == other.0.qualifiers
        }
    }
    impl Eq for TSPatternMatchWithHash {}

    // Too avoid a marking a match as changed when the change in entirely located in a sub match
    lhs.sort_by_key(|mtch| mtch.range.end_byte - mtch.range.start_byte);
    rhs.sort_by_key(|mtch| mtch.range.end_byte - mtch.range.start_byte);

    let mut lhs_changed = HashSet::new();
    for line in novel_lhs {
        for mtch in lhs
            .extract_if(|mtch| {
                // More than billions of lines in your file? too bad ;)
                mtch.range.start_point.row as u32 <= line && mtch.range.end_point.row as u32 >= line
            })
            .take(1)
        {
            lhs_changed.insert(TSPatternMatchWithHash(mtch));
        }
    }
    let mut lhs_unchanged: HashSet<_> =
        HashSet::from_iter(lhs.into_iter().map(|mtch| TSPatternMatchWithHash(mtch)));

    let mut rhs_changed = HashSet::new();
    for line in novel_rhs {
        for mtch in rhs
            .extract_if(|mtch| {
                // More than billions of lines in your file? too bad ;)
                mtch.range.start_point.row as u32 <= line && mtch.range.end_point.row as u32 >= line
            })
            .take(1)
        {
            rhs_changed.insert(TSPatternMatchWithHash(mtch));
        }
    }
    let mut rhs_unchanged: HashSet<_> =
        HashSet::from_iter(rhs.into_iter().map(|mtch| TSPatternMatchWithHash(mtch)));

    let mut diff = vec![];

    let modified = lhs_changed
        .extract_if(|lhs_mtch| rhs_changed.contains(lhs_mtch))
        .collect::<Vec<_>>()
        .into_iter()
        .filter_map(|lhs_mtch| {
            rhs_changed
                .take(&lhs_mtch)
                .filter(|rhs_mtch| {
                    lhs_mtch.0.content_hash(before_content)
                        != rhs_mtch.0.content_hash(after_content)
                })
                .map(|rhs_mtch| TSPatternMatchDiff::Modified {
                    before: lhs_mtch.0,
                    after: rhs_mtch.0,
                })
        });
    diff.extend(modified);

    let deleted_or_modified =
        lhs_changed
            .into_iter()
            .map(|lhs_mtch| match rhs_unchanged.take(&lhs_mtch) {
                Some(rhs_mtch) => TSPatternMatchDiff::Modified {
                    before: lhs_mtch.0,
                    after: rhs_mtch.0,
                },
                None => TSPatternMatchDiff::Deleted(lhs_mtch.0),
            });
    diff.extend(deleted_or_modified);

    let added_or_modified =
        rhs_changed
            .into_iter()
            .map(|rhs_mtch| match lhs_unchanged.take(&rhs_mtch) {
                Some(lhs_mtch) => TSPatternMatchDiff::Modified {
                    before: lhs_mtch.0,
                    after: rhs_mtch.0,
                },
                None => TSPatternMatchDiff::Added(rhs_mtch.0),
            });
    diff.extend(added_or_modified);

    diff
}

fn list_parsers(_global_opts: &GlobalOpts) -> anyhow::Result<()> {
    todo!("List parsers")
}

fn main() -> anyhow::Result<()> {
    let args = App::parse();

    match args.global_opts.color {
        ColorChoice::Never => {
            colored::control::set_override(false);
        }
        ColorChoice::Always => {
            colored::control::set_override(true);
        }
        _ => {}
    };

    match args.subcommand {
        Subcommands::Status { repo } => {
            print_status(repo.unwrap_or("./".to_owned()), &args.global_opts)
        }
        Subcommands::Symbols { path, tags } => print_symbols(&path, tags, &args.global_opts),
        Subcommands::Pattern(PatternSubcommands::List) => list_patterns(&args.global_opts),
        Subcommands::Pattern(PatternSubcommands::Verify) => verify_patterns(&args.global_opts),
        Subcommands::Parser(ParserSubcommands::List) => list_parsers(&args.global_opts),
    }
}
