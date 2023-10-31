use std::path::PathBuf;

use anyhow::Context;
use gix::objs::Blob;
use itertools::Itertools;

use crate::{
    git::{open, IndexEntryList, RepositoryExt},
    parser::PatternListMatcher,
};

use super::command::{AddCommand, GlobalOpts};

pub(crate) fn handle_add_command(
    command: AddCommand,
    global_opts: &GlobalOpts,
) -> anyhow::Result<()> {
    let repo = open("./").unwrap();

    let mut index = repo.open_index().unwrap();
    // Calculate status

    // Find changed symbols

    // Splice the new data, we have byte offset in our matches so should be simple.
    //  - Make sure the parent match exists

    // Write to and flush index

    // Syntax
    //
    //  Options
    //  - One command one item, e.g use -f -q -k, error if more than 1 symbols matching
    //  - One command but multiple items, e.g use -f -q -k, add all items matching
    //  - Multiple commands somehow? hard to differentiate between -q -k and -q ... -k
    //
    //  One command multiple items seems the best?? and just run the command multiple times if
    //  needed, multiple/single as a parameter?

    let untracked_entries = repo
        .untracked_entries()
        .context("Found no local file entries..")?;

    let staged_entries = repo
        .staged_entries()
        .unwrap_or_else(IndexEntryList::new_empty);

    let diff = crate::git::diff(&staged_entries, &untracked_entries);

    let mut matcher = PatternListMatcher::new(PathBuf::from(&global_opts.parser_path));

    crate::cli::pattern::load_patterns_from_opts(&mut matcher, global_opts)?;

    match (&command.file, &command.kind, &command.qualifiers) {
        (Some(_), None, None) => anyhow::bail!(
            "Only using file is not supported. Use 'git add <FILE>' for this functionalitity"
        ),
        (None, None, None) => anyhow::bail!("Kind (-k) or qualifiers (-q) must be set"),
        _ => (),
    }

    let mut changes_to_make = vec![];

    for change in diff {
        match change {
            crate::git::DiffResult::Added { path: _, content: _ } => {
                // Skip for now..
            }
            crate::git::DiffResult::Deleted { path: _, content: _ } => {
                // Skip for now..
            }
            crate::git::DiffResult::Modified {
                path,
                before_content,
                after_content,
            } => {
                if command.file.as_ref().is_some_and(|file| file != &path) {
                    continue;
                }

                let Some(pattern) = matcher.pattern_for_file_path(&path) else {
                    continue;
                };

                // We can reuse the parts of the lhs tree here..
                let lhs = pattern.matches(&before_content, None, None)?;
                let rhs = pattern.matches(&after_content, None, None)?;

                let filtered_rhs = rhs
                    .iter()
                    .cloned()
                    .filter(|mtch| {
                        command
                            .kind
                            .as_ref()
                            .map_or(true, |kind| kind == mtch.kind.as_ref())
                    })
                    .filter(|mtch| {
                        command.qualifiers.as_ref().map_or(true, |qualifiers| {
                            qualifiers
                                == &mtch
                                    .full_qualifiers
                                    .join(&pattern.qualifier_settings.seperator)
                        })
                    })
                    .collect_vec();

                for rhs_mtch in filtered_rhs {
                    if let Some(lhs_mtch) = lhs.iter().find(|mtch| {
                        mtch.kind == rhs_mtch.kind
                            && mtch.full_qualifiers == rhs_mtch.full_qualifiers
                    }) {
                        if lhs_mtch.checksum(&before_content) != rhs_mtch.checksum(&after_content) {
                            changes_to_make.push((
                                path.clone(),
                                lhs_mtch.clone(),
                                rhs_mtch,
                                after_content.clone(),
                            )); // Use rc instead?
                        }
                    } else {
                        todo!("Adding new symbols is yet to be implemented..")
                    }
                }
            }
        }
    }

    for (path, lhs, rhs, rhs_content) in changes_to_make {
        // TODO: Handle multi range matches
        assert!(lhs.ranges.borrow().len() == 1);
        let lhs_range = *lhs.ranges.borrow().first().unwrap();

        assert!(rhs.ranges.borrow().len() == 1);
        let rhs_range = *rhs.ranges.borrow().first().unwrap();

        let entry = index
            .entry_mut_by_path_and_stage(path.as_str().into(), 0)
            .unwrap();

        let object = repo.find_object(entry.id)?.try_into_blob()?;

        let new_data = &rhs_content[rhs_range.start_byte..rhs_range.end_byte];
        let mut data = object.data.clone();
        let _removed = data
            .splice(
                lhs_range.start_byte..lhs_range.end_byte,
                new_data.iter().cloned(),
            )
            .collect_vec();
        let new_blob = Blob { data };
        let id = repo.write_object(new_blob)?;

        entry.id = id.into();

        index.write(gix::index::write::Options::default())?;
    }

    Ok(())
}
