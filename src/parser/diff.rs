use itertools::Itertools;
use std::{
    collections::{hash_map::Entry, HashMap},
    rc::Rc,
};

use super::{
    symbol::{Symbol, SymbolChange},
    PatternList, PatternListMatcher, PatternMatch,
};

// TODO: Create diff_file version that has access to tree and matches cache and can be used in history

pub fn diff_file(
    file_path: &str,
    matcher: &PatternListMatcher,
    before: Option<&[u8]>,
    after: Option<&[u8]>,
    include_children: bool,
) -> anyhow::Result<Vec<SymbolChange>> {
    let Some(pattern) = matcher.pattern_for_file_path(file_path) else {
        let file_symbol_change = match (before, after) {
            (Some(before), None) => SymbolChange::Added {
                symbol: Symbol {
                    kind: "file".into(),
                    qualifiers: "".into(),
                    file_path: file_path.into(),
                },
                novel_rhs: String::from_utf8(before.to_vec()).unwrap().lines().count(),
            },
            (None, Some(after)) => SymbolChange::Added {
                symbol: Symbol {
                    kind: "file".into(),
                    qualifiers: "".into(),
                    file_path: file_path.into(),
                },
                novel_rhs: String::from_utf8(after.to_vec())?.lines().count(),
            },
            (Some(before), Some(after)) => {
                let (novel_lhs, novel_rhs) = crate::diff::diff(before, after);
                SymbolChange::Modified {
                    symbol: Symbol {
                        kind: "file".into(),
                        qualifiers: "".into(),
                        file_path: file_path.into(),
                    },
                    novel_lhs: novel_lhs.len(),
                    novel_rhs: novel_rhs.len(),
                }
            }
            (None, None) => unreachable!("This should never happen. Please submit an issue"),
        };

        return Ok(vec![file_symbol_change]);
    };

    let symbols: Vec<_> = match (before, after) {
        (None, Some(after)) => {
            let tree = pattern.parse(after, None)?;
            pattern
                .matches(after, Some(&tree), None)?
                .into_iter()
                .map(|mtch| SymbolChange::from_added_match(mtch, file_path, pattern))
                .chain(std::iter::once(SymbolChange::Added {
                    symbol: Symbol {
                        kind: "file".into(),
                        qualifiers: "".into(),
                        file_path: file_path.into(),
                    },
                    novel_rhs: tree.root_node().range().end_point.row,
                }))
                .collect()
        }
        (Some(before), None) => {
            let tree = pattern.parse(before, None)?;
            pattern
                .matches(before, Some(&tree), None)?
                .into_iter()
                .map(|mtch| SymbolChange::from_deleted_match(mtch, file_path, pattern))
                .chain(std::iter::once(SymbolChange::Deleted {
                    symbol: Symbol {
                        kind: "file".into(),
                        qualifiers: "".into(),
                        file_path: file_path.into(),
                    },
                    novel_lhs: tree.root_node().range().end_point.row,
                }))
                .collect()
        }
        (Some(before), Some(after)) => {
            let lhs = pattern.matches(before, None, None)?;
            let rhs = pattern.matches(after, None, None)?;
            let (novel_lhs, novel_rhs) = crate::diff::diff(before, after);
            let file_symbol_change = SymbolChange::Modified {
                symbol: Symbol {
                    kind: "file".into(),
                    qualifiers: "".into(),
                    file_path: file_path.into(),
                },
                novel_lhs: novel_lhs.len(),
                novel_rhs: novel_rhs.len(),
            };
            let mut symbols = diff_matches(
                file_path,
                pattern,
                lhs,
                rhs,
                novel_lhs,
                novel_rhs,
                include_children,
            );
            symbols.push(file_symbol_change);
            symbols
        }
        (None, None) => unreachable!("This should never happen. Please submit an issue"),
    };

    Ok(symbols)
}

fn diff_matches(
    file_path: &str,
    pattern: &PatternList,
    lhs: Vec<Rc<PatternMatch>>,
    rhs: Vec<Rc<PatternMatch>>,
    novel_lhs: Vec<u32>,
    novel_rhs: Vec<u32>,
    include_children: bool,
) -> Vec<SymbolChange> {
    struct MatchWithNovelLines {
        lhs_match: Option<Rc<PatternMatch>>,
        rhs_match: Option<Rc<PatternMatch>>,
        novel_lhs: Vec<usize>,
        novel_rhs: Vec<usize>,
    }

    let mut lhs = lhs
        .into_iter()
        .sorted_by_key(|mtch| mtch.range_byte_count())
        .map(|mtch| (mtch, vec![]))
        .collect_vec();
    for line in novel_lhs {
        for (mtch, novel) in lhs.iter_mut() {
            if mtch.contains_line(line as usize) {
                novel.push(line as usize);
                // This has the same problems as earlier implementations in status.
                // When an match is contained within a single line.
                if !include_children {
                    break;
                }
            }
        }
    }

    let mut rhs = rhs
        .into_iter()
        .sorted_by_key(|mtch| mtch.range_byte_count())
        .map(|mtch| (mtch, vec![]))
        .collect_vec();
    for line in novel_rhs {
        for (mtch, novel) in rhs.iter_mut() {
            if mtch.contains_line(line as usize) {
                novel.push(line as usize);
                // This has the same problems as earlier implementations in status.
                // When an match is contained within a single line.
                if !include_children {
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
        }
    }

    changes
        .into_iter()
        .filter(|(_, change)| !change.novel_lhs.is_empty() || !change.novel_rhs.is_empty())
        .map(
            |(_, mut change)| match (change.lhs_match.take(), change.rhs_match.take()) {
                // Should we calculate checksum and check that is does not match??
                (Some(lhs), Some(_rhs)) => SymbolChange::Modified {
                    symbol: Symbol::new(lhs, file_path, pattern),
                    novel_lhs: change.novel_lhs.len(),
                    novel_rhs: change.novel_rhs.len(),
                },
                (None, Some(rhs)) => SymbolChange::Added {
                    symbol: Symbol::new(rhs, file_path, pattern),
                    novel_rhs: change.novel_rhs.len(),
                },
                (Some(lhs), None) => SymbolChange::Deleted {
                    symbol: Symbol::new(lhs, file_path, pattern),
                    novel_lhs: change.novel_lhs.len(),
                },
                (None, None) => unreachable!(),
            },
        )
        .collect()
}
