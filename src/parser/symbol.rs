use std::rc::Rc;

use itertools::Itertools;

use super::{PatternMatch, PatternList};

#[derive(Debug, serde::Serialize)]
pub struct SymbolRange {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_row: usize,
    pub start_col: usize,
    pub end_row: usize,
    pub end_col: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct SymbolWithRanges {
    pub kind: String,
    pub qualifiers: String,
    pub file_path: String,
    pub ranges: Vec<SymbolRange>
}

impl SymbolWithRanges {
    pub fn new(mtch: Rc<PatternMatch>, file_path: &str, pattern: &PatternList) -> Self {
        Self {
            kind: mtch.kind.to_string(),
            qualifiers: mtch
                .full_qualifiers
                .join(&pattern.qualifier_settings.seperator),
            file_path: file_path.to_string(),
            ranges: mtch.ranges.take().into_iter().map(|range| SymbolRange {
                start_byte: range.start_byte,
                end_byte: range.end_byte,
                start_row: range.start_point.row,
                start_col: range.start_point.column,
                end_row: range.end_point.row,
                end_col: range.end_point.column,

            }).collect()
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct Symbol {
    pub kind: String,
    pub qualifiers: String,
    pub file_path: String,
}

impl Symbol {
    pub fn new(mtch: Rc<PatternMatch>, file_path: &str, pattern: &PatternList) -> Self {
        Self {
            kind: mtch.kind.to_string(),
            qualifiers: mtch
                .full_qualifiers
                .join(&pattern.qualifier_settings.seperator),
            file_path: file_path.to_string(),
        }
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(tag = "change", rename_all = "lowercase")]
pub enum SymbolChange {
    Added {
        #[serde(flatten)]
        symbol: Symbol,
        novel_rhs: usize,
    },
    Modified {
        #[serde(flatten)]
        symbol: Symbol,
        novel_lhs: usize,
        novel_rhs: usize,
    },
    Deleted {
        #[serde(flatten)]
        symbol: Symbol,
        novel_lhs: usize,
    },
}

impl SymbolChange {
    pub fn symbol(&self) -> &Symbol {
        match self {
            Self::Added { symbol, .. } => symbol,
            Self::Deleted { symbol, .. } => symbol,
            Self::Modified { symbol, .. } => symbol,
        }
    }

    pub fn from_deleted_match(
        mtch: Rc<PatternMatch>,
        file_path: &str,
        pattern: &PatternList,
    ) -> Self {
        Self::Deleted {
            novel_lhs: mtch.range_line_count(),
            symbol: Symbol::new(mtch, file_path, pattern),
        }
    }

    pub fn from_added_match(
        mtch: Rc<PatternMatch>,
        file_path: &str,
        pattern: &PatternList,
    ) -> Self {
        Self::Added {
            novel_rhs: mtch.range_line_count(),
            symbol: Symbol::new(mtch, file_path, pattern),
        }
    }
}

pub fn group_symbol_changes_by_files(symbols: Vec<SymbolChange>) -> Vec<(SymbolChange, Vec<SymbolChange>)> {
    let (files, symbols): (Vec<_>, Vec<_>) = symbols.into_iter().partition(|change| change.symbol().kind == "file");

    let mut files = files.into_iter().map(|symbol| (symbol, vec![])).collect_vec();

    for symbol in symbols {
        let Some((_, file_symbols)) = files.iter_mut().find(|(file, _)| file.symbol().file_path == symbol.symbol().file_path) else {
            continue;
        };

        file_symbols.push(symbol);
    }

    files.sort_by(|(lhs, _), (rhs, _)| lhs.symbol().file_path.cmp(&rhs.symbol().file_path));

    files
}
