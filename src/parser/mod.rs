pub mod diff;
mod provider;
pub mod symbol;
use itertools::Itertools;
use provider::TSLanguageProvider;
pub use provider::TSParser;
use serde::Deserialize;
use std::{
    cell::RefCell,
    collections::HashMap,
    path::{Path, PathBuf},
    rc::Rc,
    str::FromStr,
    sync::{Arc, Mutex},
};
use thiserror::Error;

trait RangeExt {
    fn contains(&self, other: &Self) -> bool;
}
impl RangeExt for tree_sitter::Range {
    fn contains(&self, other: &Self) -> bool {
        self.start_byte <= other.start_byte && self.end_byte >= other.end_byte
    }
}

pub type Kind = Rc<str>;
pub type Qualifiers = Vec<Rc<str>>;

#[derive(Debug, PartialEq, Eq)]
pub struct PatternMatch {
    pub kind: Kind,
    pub qualifiers: Qualifiers,
    pub full_qualifiers: Qualifiers,
    // Most of the time it will only contain a single element. tiny vec would be better but the
    // performance difference is probably miniscule
    pub ranges: RefCell<Vec<tree_sitter::Range>>,
    pub parent: Option<Rc<PatternMatch>>,
    pub hidden: bool,
}

impl PatternMatch {
    pub fn checksum(&self, data: &[u8]) -> u32 {
        let mut adler = adler::Adler32::new();
        for range in self.ranges.borrow().iter() {
            adler.write_slice(&data[range.start_byte..range.end_byte]);
        }
        adler.checksum()
    }

    pub fn add_range(&self, range: tree_sitter::Range) {
        // TODO: Should also probably try to merge the range with existing range if it is overlapping
        self.ranges.borrow_mut().push(range);
    }

    pub fn contains_line(&self, line: usize) -> bool {
        self.ranges
            .borrow()
            .iter()
            .any(|range| range.start_point.row <= line && range.end_point.row >= line)
    }

    pub fn contains_point(&self, point: tree_sitter::Point) -> bool {
        self.ranges
            .borrow()
            .iter()
            .any(|range| range.start_point <= point && range.end_point >= point)
    }

    pub fn range_line_count(&self) -> usize {
        self.ranges
            .borrow()
            .iter()
            .map(|range| range.end_point.row - range.start_point.row + 1)
            .sum()
    }

    pub fn range_byte_count(&self) -> usize {
        self.ranges
            .borrow()
            .iter()
            .map(|range| range.end_byte - range.start_byte + 1)
            .sum()
    }

    #[allow(dead_code)]
    pub fn range_first_byte(&self) -> usize {
        self.ranges
            .borrow()
            .iter()
            .map(|range| range.start_byte)
            .min()
            .unwrap_or(0)
    }
}

#[derive(Deserialize, Debug)]
struct PatternFilter {
    operator: String,
    capture: String,
    value: String,
}

#[derive(Deserialize, Debug)]
pub struct Pattern {
    query: String,
    range_capture: Vec<String>,
    identifier_capture: Vec<String>,
    kind: Rc<str>,
    filters: Option<Vec<PatternFilter>>,
    hidden: Option<bool>,
}

#[derive(Error, Debug)]
pub enum PatternError {
    #[error("No captures for range..")]
    NoRangeCapture,
    #[error("No capture for identifier for {identifier}")]
    NoIdentifierCapture { identifier: String },
    #[error("Node contained invalid UTF-8")]
    InvalidUtf8(#[from] core::str::Utf8Error),
    #[error("Unsupported filter, {0}")]
    UnsupportedFilter(String),
}

enum TransformedMatch {
    None,
    New(PatternMatch),
    Existing(Rc<PatternMatch>),
}

impl Pattern {
    fn passes_filters(
        &self,
        query: &tree_sitter::Query,
        mtch: &tree_sitter::QueryMatch,
        source: &[u8],
    ) -> Result<bool, PatternError> {
        if let Some(filters) = &self.filters {
            for filter in filters {
                let idx = query
                    .capture_index_for_name(&filter.capture)
                    .expect("Internal error in query..");
                let captures: Vec<_> = mtch.nodes_for_capture_index(idx).collect();

                match filter.operator.as_str() {
                    "contains" => {
                        if captures.iter().all(|node| {
                            node.utf8_text(source)
                                .map(|text| text != filter.value)
                                .unwrap_or(false)
                        }) || captures.is_empty()
                        {
                            return Ok(false);
                        }
                    }
                    "not-contains" => {
                        if captures.iter().any(|node| {
                            node.utf8_text(source)
                                .map(|text| text == filter.value)
                                .unwrap_or(false)
                        }) && !captures.is_empty()
                        {
                            return Ok(false);
                        }
                    }
                    filter => return Err(PatternError::UnsupportedFilter(filter.into())),
                }
            }
        }

        Ok(true)
    }

    fn range(
        &self,
        query: &tree_sitter::Query,
        mtch: &tree_sitter::QueryMatch,
    ) -> Result<tree_sitter::Range, PatternError> {
        let mut range: Option<tree_sitter::Range> = None;

        for range_capture in self.range_capture.iter() {
            let idx = query
                .capture_index_for_name(range_capture)
                .expect("Internal error in query..");

            for capture in mtch.captures.iter().filter(|c| c.index == idx) {
                let node_range = capture.node.range();

                if let Some(range) = range.as_mut() {
                    if node_range.start_byte < range.start_byte {
                        range.start_byte = node_range.start_byte;
                        range.start_point = node_range.start_point;
                    }
                    if node_range.end_byte > range.end_byte {
                        range.end_byte = node_range.end_byte;
                        range.end_point = node_range.end_point;
                    }
                } else {
                    range = Some(node_range);
                }
            }
        }

        range.ok_or(PatternError::NoRangeCapture)
    }

    fn qualifiers(
        &self,
        query: &tree_sitter::Query,
        mtch: &tree_sitter::QueryMatch,
        source: &[u8],
    ) -> Result<Vec<Rc<str>>, PatternError> {
        self.identifier_capture
            .iter()
            .map(|id| {
                query
                    .capture_index_for_name(id)
                    .expect("Internal error in query..")
            })
            .map(|idx| {
                let capture = mtch.captures.iter().find(|c| c.index == idx).ok_or(
                    PatternError::NoIdentifierCapture {
                        identifier: query.capture_names()[idx as usize].clone(),
                    },
                )?;
                let text = capture.node.utf8_text(source)?;

                Ok(text.into())
            })
            .collect()
    }

    fn transform_match(
        &self,
        query: &tree_sitter::Query,
        mtch: &tree_sitter::QueryMatch,
        source: &[u8],
        qualified_matches: &HashMap<(Kind, Qualifiers), Rc<PatternMatch>>,
        matches: &[Rc<PatternMatch>],
    ) -> Result<TransformedMatch, PatternError> {
        let passes_filters = self.passes_filters(query, mtch, source)?;

        if !passes_filters {
            return Ok(TransformedMatch::None);
        }

        let range = self.range(query, mtch)?;
        let qualifiers = self.qualifiers(query, mtch, source)?;
        let kind = self.kind.clone();
        let mut parent_qualifiers = vec![];

        let mut maybe_parent = matches.last();
        let mut parent = None;

        'outer: while let Some(candidate_parent) = maybe_parent {
            for candidate_parent_range in candidate_parent.ranges.borrow().iter() {
                if candidate_parent_range.contains(&range) {
                    parent_qualifiers = candidate_parent.full_qualifiers.clone();
                    parent = Some(candidate_parent.clone());
                    break 'outer;
                }

                maybe_parent = candidate_parent.parent.as_ref();
            }
        }

        parent_qualifiers.extend(qualifiers.clone());

        let full_qualifiers = parent_qualifiers;

        if let Some(mtch) = qualified_matches.get(&(kind.clone(), full_qualifiers.clone())) {
            mtch.add_range(range);
            return Ok(TransformedMatch::Existing(mtch.clone()));
        }

        Ok(TransformedMatch::New(PatternMatch {
            kind,
            qualifiers,
            full_qualifiers,
            ranges: RefCell::new(vec![range]),
            parent,
            hidden: self.hidden == Some(true),
        }))
    }
}

#[derive(Deserialize, Default)]
pub struct QualifierSettings {
    pub seperator: String,
}

#[derive(Error, Debug)]
pub enum CreatePatternListError {
    #[error("File not found: {0}")]
    FileNotFound(#[from] std::io::Error),
    #[error("Invalid TOML: {0}")]
    InvalidTOML(#[from] toml::de::Error),
}

#[derive(Error, Debug)]
pub enum PatternListError {
    #[error("{0}")]
    Transient(#[from] Arc<PatternListError>),
    #[error("Failed to set parser langauge")]
    Language(#[from] tree_sitter::LanguageError),
    #[error("Failed to fetch parser langauge. {0}")]
    FetchLanguage(#[from] anyhow::Error),
    #[error("Failed to create query: {0}")]
    Query(#[from] tree_sitter::QueryError),
    #[error("Invalid pattern, pattern uses capture \"{0}\" that is not present in query")]
    InvalidCaptureInPattern(String),
    #[error("Invalid pattern, pattern has no range capture")]
    MissingRangeCaptureInPattern,
    #[error("Invalid pattern, pattern has no identifier capture")]
    MissingIdentifierCaptureInPattern,
    #[error("Parsing returned no tree")]
    Parsing,
    #[error("Error when creating a match")]
    Match(#[from] PatternError),
}

pub struct PatternList {
    pub identifier: PatternIdentifier,
    pub qualifier_settings: QualifierSettings,
    pub hash: u32,
    pub patterns: Vec<Pattern>,
    pub parser: TSParser,
    file_filter: PatternFileFilter,
    language_provider: Arc<Mutex<TSLanguageProvider>>,
    query: std::cell::OnceCell<Result<tree_sitter::Query, Arc<PatternListError>>>,
    language: std::cell::OnceCell<Result<tree_sitter::Language, Arc<PatternListError>>>,
}

#[derive(Deserialize)]
struct PatternFileFilter {
    exact_file_name: Option<Vec<String>>,
    file_types: Option<Vec<String>>,
}

impl PatternList {
    fn from_toml_content(
        identifier: &PatternIdentifier,
        data: &str,
        language_provider: Arc<Mutex<TSLanguageProvider>>,
    ) -> Result<Self, CreatePatternListError> {
        #[derive(Deserialize)]
        struct PartialPatternsList {
            #[serde(default)]
            pattern: Vec<Pattern>,
            parser: TSParser,
            #[serde(default)]
            qualifier: QualifierSettings,
            file: PatternFileFilter,
        }

        let list: PartialPatternsList = toml::from_str(data)?;

        Ok(Self {
            identifier: identifier.clone(),
            hash: adler::adler32_slice(data.as_bytes()),
            language: std::cell::OnceCell::new(),
            query: std::cell::OnceCell::new(),
            parser: list.parser,
            qualifier_settings: list.qualifier,
            patterns: list.pattern,
            file_filter: list.file,
            language_provider,
        })
    }
    fn from_toml(
        path: &PathBuf,
        language_provider: Arc<Mutex<TSLanguageProvider>>,
    ) -> Result<Self, CreatePatternListError> {
        let data = std::fs::read_to_string(path)?;

        Self::from_toml_content(
            &PatternIdentifier::Local { path: path.clone() },
            &data,
            language_provider,
        )
    }

    /// Try to load the [tree_sitter::Language] specified in the config and create and verify the
    /// [tree_sitter::Query]
    pub fn verify(&self) -> Result<(), PatternListError> {
        self.language()?;
        self.query()?;
        Ok(())
    }

    fn filter_file_path(&self, path: &Path) -> bool {
        match &self.file_filter.exact_file_name {
            Some(names) => {
                if let Some(file_name) = path.file_name().and_then(|e| e.to_str()) {
                    if names.iter().map(String::as_str).contains(&file_name) {
                        return true;
                    }
                }
            }
            None => {}
        }

        match &self.file_filter.file_types {
            Some(types) => {
                let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if types.iter().map(String::as_str).contains(&extension) {
                    return true;
                }
            }

            None => {}
        }

        false
    }

    fn language(&self) -> Result<tree_sitter::Language, PatternListError> {
        match self
            .language
            .get_or_init(|| self.fetch_language().map_err(Arc::new))
        {
            Ok(lang) => Ok(*lang),
            Err(err) => Err(PatternListError::Transient(err.clone())),
        }
    }

    fn fetch_language(&self) -> Result<tree_sitter::Language, PatternListError> {
        let mut provider = self
            .language_provider
            .lock()
            .expect("Mutex should not be poisoned");

        Ok(match provider.language_for_parser(&self.parser) {
            Some(lang) => lang,
            None => provider
                .create_language_for_parser(&self.parser)
                .map_err(PatternListError::FetchLanguage)?,
        })
    }

    fn query(&self) -> Result<&tree_sitter::Query, PatternListError> {
        match self
            .query
            .get_or_init(|| self.create_query().map_err(Arc::new))
        {
            Ok(query) => Ok(query),
            Err(err) => Err(PatternListError::Transient(err.clone())),
        }
    }

    fn create_query(&self) -> Result<tree_sitter::Query, PatternListError> {
        let raw_query = self
            .patterns
            .iter()
            .map(|pattern| &pattern.query)
            .join("\n");
        let language = self.language()?;
        // TODO: if this fails we should check all patterns to find out which ones have the error
        let query = tree_sitter::Query::new(language, &raw_query)?;

        // TODO: We should accumulate all erros and not only return first error
        for pattern in self.patterns.iter() {
            if pattern.range_capture.is_empty() {
                return Err(PatternListError::MissingRangeCaptureInPattern);
            }
            if pattern.identifier_capture.is_empty() {
                return Err(PatternListError::MissingIdentifierCaptureInPattern);
            }

            for capture in pattern
                .range_capture
                .iter()
                .chain(pattern.identifier_capture.iter())
            {
                if query.capture_index_for_name(capture.as_str()).is_none() {
                    return Err(PatternListError::InvalidCaptureInPattern(capture.clone()));
                }
            }
        }

        Ok(tree_sitter::Query::new(language, &raw_query)?)
    }

    fn matches_from_tree(
        &self,
        data: &[u8],
        tree: &tree_sitter::Tree,
    ) -> Result<Vec<Rc<PatternMatch>>, PatternListError> {
        let node = tree.root_node();

        let query = self.query()?;

        // Could be optimized to only capture edited data.. would require multiple passes.. Some
        // heurestic might be needed.. depends on the cost of multiple matches vs one big match..
        let mut cursor = tree_sitter::QueryCursor::new();
        let matches = cursor.matches(query, node, data);

        let mut transformed_matches = vec![];
        let mut qualified_matches = HashMap::new();
        for mtch in matches {
            let pattern = self
                .patterns
                .get(mtch.pattern_index)
                .expect("There is a one to one match between pattern and pattern index");

            let transformed_match = pattern.transform_match(
                query,
                &mtch,
                data,
                &qualified_matches,
                &transformed_matches,
            )?;

            match transformed_match {
                TransformedMatch::None => continue,
                TransformedMatch::New(mtch) => {
                    let transformed_match = Rc::new(mtch);
                    transformed_matches.push(transformed_match.clone());
                    qualified_matches.insert(
                        (
                            transformed_match.kind.clone(),
                            transformed_match.full_qualifiers.clone(),
                        ),
                        transformed_match,
                    );
                }
                TransformedMatch::Existing(mtch) => {
                    transformed_matches.push(mtch);
                }
            }
        }

        let matches = transformed_matches.into_iter().unique_by(|mtch| (mtch.kind.clone(), mtch.full_qualifiers.clone())).collect();

        Ok(matches)
    }
    /// Parse a [tree_sitter::Tree] from a UTF8 source
    /// # Arguements
    /// * `data` UTF8 encoded source to parse
    /// * `old_tree` passed to [tree_sitter::Parser::parse] to only reparse certan parts of source
    pub fn parse(
        &self,
        data: &[u8],
        old_tree: Option<&tree_sitter::Tree>,
    ) -> Result<tree_sitter::Tree, PatternListError> {
        let mut parser = tree_sitter::Parser::new();
        let language = self.language()?;
        parser.set_language(language)?;

        parser
            .parse(data, old_tree)
            .ok_or(PatternListError::Parsing)
    }

    /// Get all matches from UTF8 source
    /// # Arguements:
    /// * `data` UTF8 encoded source to parse
    /// * `tree` use an existing [tree_sitter::Tree] to avoid reparsing
    /// * `old_tree` if no tree is provided, passes old_tree to [tree_sitter::Parser::parse] to only
    /// reparse certain parts of source
    pub fn matches(
        &self,
        data: &[u8],
        tree: Option<&tree_sitter::Tree>,
        old_tree: Option<&tree_sitter::Tree>,
    ) -> Result<Vec<Rc<PatternMatch>>, PatternListError> {
        if let Some(tree) = tree {
            self.matches_from_tree(data, tree)
        } else {
            self.matches_from_tree(data, &self.parse(data, old_tree)?)
        }
    }
}

#[derive(Error, Debug)]
pub enum LoadPatternsError {
    #[error("Could not read from directory: {0}")]
    ReadFromDirectory(#[from] std::io::Error),
}

pub struct PatternListMatcher {
    pub patterns: Vec<PatternList>,
    // Can be a bottleneck to have this as an arc mutex, could be rw lock with a rw lock on each
    // "row" in the hashmap. This would allow reading some languages while compiling others. Would
    // only help when the langauges are not precompiled.
    language_provider: Arc<Mutex<TSLanguageProvider>>,
}

#[derive(Debug, Clone)]
pub enum PatternIdentifier {
    Default { name: String },
    Local { path: PathBuf },
}

impl std::fmt::Display for PatternIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatternIdentifier::Default { name } => {
                f.write_fmt(format_args!("{} (core pattern)", name))
            }
            PatternIdentifier::Local { path } => f.write_str(&path.display().to_string()),
        }
    }
}

type LoadPatternResult = (PatternIdentifier, Result<(), CreatePatternListError>);
impl PatternListMatcher {
    pub fn new(parser_path: PathBuf) -> Self {
        Self {
            patterns: vec![],
            language_provider: Arc::new(Mutex::new(TSLanguageProvider::from_parser_path(
                parser_path,
            ))),
        }
    }

    pub fn load_patterns(
        &mut self,
        patterns_path: &str,
    ) -> Result<Vec<LoadPatternResult>, LoadPatternsError> {
        let mut results = vec![];
        for file in std::fs::read_dir(patterns_path)? {
            let res = match file.as_ref().map(|file| (file, file.file_type())) {
                Ok((file, Ok(file_type))) => {
                    if !file_type.is_file() {
                        continue;
                    }

                    let path = file.path();

                    let result = match PatternList::from_toml(&path, self.language_provider.clone())
                    {
                        Ok(pattern) => {
                            self.patterns.push(pattern);
                            Ok(())
                        }
                        Err(err) => Err(err),
                    };

                    (PatternIdentifier::Local { path }, result)
                }
                _ => continue,
            };
            results.push(res);
        }
        Ok(results)
    }

    pub fn load_default_patterns(&mut self) -> Vec<LoadPatternResult> {
        let patterns = [
            ("rust", include_str!("../../patterns/rust.toml")),
            ("csharp", include_str!("../../patterns/csharp.toml")),
            ("c", include_str!("../../patterns/c.toml")),
            ("ocaml", include_str!("../../patterns/ocaml.toml")),
            ("toml", include_str!("../../patterns/toml.toml")),
            ("json", include_str!("../../patterns/json.toml")),
            ("lua", include_str!("../../patterns/lua.toml")),
            ("typescript", include_str!("../../patterns/typescript.toml")),
            ("javascript", include_str!("../../patterns/javascript.toml")),
            ("go", include_str!("../../patterns/go.toml")),
        ];

        patterns
            .into_iter()
            .map(|(name, pattern)| {
                let identifier = PatternIdentifier::Default { name: name.into() };
                let result = match PatternList::from_toml_content(
                    &identifier,
                    pattern,
                    self.language_provider.clone(),
                ) {
                    Ok(pattern) => {
                        self.patterns.push(pattern);
                        Ok(())
                    }
                    Err(err) => Err(err),
                };

                (PatternIdentifier::Default { name: name.into() }, result)
            })
            .collect()
    }

    pub fn pattern_for_file_path(&self, file_path: &str) -> Option<&'_ PatternList> {
        let file_path = PathBuf::from_str(file_path).ok()?;

        self.patterns
            .iter()
            .find(|pattern| pattern.filter_file_path(&file_path))
    }
}

#[cfg(test)]
mod tests {
    use super::{provider::TSLanguageProvider, CreatePatternListError};
    use super::{PatternIdentifier, PatternList, PatternMatch};
    use pretty_assertions::{assert_eq, assert_ne};
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::{
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };

    fn create_pattern(toml: &str) -> Result<PatternList, CreatePatternListError> {
        let language_provider = Arc::new(Mutex::new(TSLanguageProvider::from_parser_path(
            ".intelligit".into(),
        )));
        PatternList::from_toml_content(
            &PatternIdentifier::Local {
                path: PathBuf::from("test.toml"),
            },
            toml,
            language_provider,
        )
    }

    #[test]
    fn valid_pattern_list_toml() {
        assert!(create_pattern(
            r#"
            [parser]
            path = "./local_parser"

            [qualifier]
            seperator = "::"

            [file]
            file_types=["rs"]

            [[pattern]]
            kind="struct"
            query="(struct_item) @struct"
            range_capture=["struct"]
            identifier_capture=["struct"]
        "#
        )
        .is_ok());

        assert!(create_pattern(
            r#"
            parser = { path = "./local_parser" }
            qualifier = { seperator = "::" }
            file = { file_types = ["rs"], exact_file_name = ["Cargo.toml"] }

            [[pattern]]
            kind="struct"
            query="(struct_item) @struct"
            range_capture=["struct"]
            identifier_capture=["struct"]
        "#
        )
        .is_ok());
    }

    #[test]
    fn invalid_pattern_list_toml() {
        // Missing parser
        assert!(create_pattern(
            r#"
            [file]
            file_types=["rs"]

            [[pattern]]
            kind="struct"
            query="(struct_item) @struct"
            range_capture=["struct"]
            identifier_capture=["struct"]
        "#
        )
        .is_err());

        // Missing file
        assert!(create_pattern(
            r#"
            [parser]
            path = "./local_parser"

            [[pattern]]
            kind="struct"
            query="(struct_item) @struct"
            range_capture=["struct"]
            identifier_capture=["struct"]
        "#
        )
        .is_err());
    }

    #[test]
    fn missing_identifier_capture() {
        assert!(create_pattern(
            r#"
            parser = { url = "https://github.com/tree-sitter/tree-sitter-rust" }
            file = { file_types = ["rs"], exact_file_name = ["package.json"] }
            [[pattern]]
            kind="fn"
            query="""
            (function_item
            name: (identifier) @name) @fn"""
            range_capture=["fn"]
            identifier_capture=[]
        "#,
        )
        .unwrap()
        .verify()
        .is_err());
    }

    #[test]
    fn missing_range_capture() {
        assert!(create_pattern(
            r#"
            parser = { url = "https://github.com/tree-sitter/tree-sitter-rust" }
            file = { file_types = ["rs"], exact_file_name = ["package.json"] }
            [[pattern]]
            kind="fn"
            query="""
            (function_item
            name: (identifier) @name) @fn"""
            range_capture=[]
            identifier_capture=["name"]
        "#,
        )
        .unwrap()
        .verify()
        .is_err());
    }

    #[test]
    fn range_capture_not_in_query() {
        assert!(create_pattern(
            r#"
            parser = { url = "https://github.com/tree-sitter/tree-sitter-rust" }
            file = { file_types = ["rs"], exact_file_name = ["package.json"] }
            [[pattern]]
            kind="fn"
            query="""
            (function_item
            name: (identifier) @name) @fn"""
            range_capture=["missing"]
            identifier_capture=["name"]
        "#,
        )
        .unwrap()
        .verify()
        .is_err());
    }

    #[test]
    fn identifier_capture_not_in_query() {
        assert!(create_pattern(
            r#"
            parser = { url = "https://github.com/tree-sitter/tree-sitter-rust" }
            file = { file_types = ["rs"], exact_file_name = ["package.json"] }
            [[pattern]]
            kind="fn"
            query="""
            (function_item
            name: (identifier) @name) @fn"""
            range_capture=["fn"]
            identifier_capture=["name", "missing"]
        "#,
        )
        .unwrap()
        .verify()
        .is_err());
    }

    #[test]
    fn different_patterns_have_different_hashes() {
        let lhs_toml = r#"
        [parser]
        path = "./local_parser"

        [file]
        file_types=["rs"]

        [[pattern]]
        kind="struct"
        query="""
        (struct_item
          name: (type_identifier) @name) @struct"""
        range_capture=["struct"]
        identifier_capture=["name"]

        "#
        .to_string();

        let lhs = create_pattern(&lhs_toml).unwrap().hash;

        let extra_pattern = r#"
        [[pattern]]
        kind="enum"
        query="""
        (enum_item
          name: (type_identifier) @name) @enum"""
        range_capture=["enum"]
        identifier_capture=["name"]
        "#;

        let rhs_toml = lhs_toml + extra_pattern;

        let rhs = create_pattern(&rhs_toml).unwrap().hash;

        assert_ne!(lhs, rhs);
    }

    #[test]
    fn pattern_list_file_filter() {
        let pattern = create_pattern(
            r#"
            parser = { precompiled = "rust" }
            file = { file_types = ["rs"], exact_file_name = ["package.json"] }
            [[pattern]]
            kind="struct"
            query="(struct_item) @struct"
            range_capture=["struct"]
            identifier_capture=["struct"]
            "#,
        )
        .unwrap();
        assert!(!pattern.filter_file_path(Path::new("test.h")));
        assert!(!pattern.filter_file_path(Path::new("/cli/src.long-name-ending-with-rs")));
        assert!(!pattern.filter_file_path(Path::new("different.json")));
        assert!(pattern.filter_file_path(Path::new("./cli/src/main.rs")));
        assert!(pattern.filter_file_path(Path::new("package.json")));
    }

    #[test]
    fn matches_for_tree() {
        let pattern = create_pattern(
            r#"
            parser = { precompiled = "rust" }
            file = { file_types = ["rs"], exact_file_name = ["package.json"] }
            [[pattern]]
            kind="struct"
            query="""
            (struct_item
            name: (type_identifier) @name) @struct"""
            range_capture=["struct"]
            identifier_capture=["name"]
        "#,
        )
        .unwrap();
        let source = b"
struct Foo {
    n: i32
}
        
struct Bar;
        ";

        let matches = pattern.matches(source, None, None).unwrap();

        let expected_matches = vec![
            Rc::new(PatternMatch {
                hidden: false,
                kind: "struct".into(),
                qualifiers: vec!["Foo".into()],
                full_qualifiers: vec!["Foo".into()],
                parent: None,
                ranges: RefCell::new(vec![tree_sitter::Range {
                    start_byte: 1,
                    end_byte: 26,
                    start_point: tree_sitter::Point { row: 1, column: 0 },
                    end_point: tree_sitter::Point { row: 3, column: 1 },
                }]),
            }),
            Rc::new(PatternMatch {
                hidden: false,
                kind: "struct".into(),
                qualifiers: vec!["Bar".into()],
                full_qualifiers: vec!["Bar".into()],
                parent: None,
                ranges: RefCell::new(vec![tree_sitter::Range {
                    start_byte: 36,
                    end_byte: 47,
                    start_point: tree_sitter::Point { row: 5, column: 0 },
                    end_point: tree_sitter::Point { row: 5, column: 11 },
                }]),
            }),
        ];

        assert_eq!(expected_matches, matches);
    }

    #[test]
    fn nested_matches() {
        let pattern = create_pattern(
            r#"
            parser = { precompiled = "rust" }
            file = { file_types = ["rs"], exact_file_name = ["package.json"] }
            [[pattern]]
            kind="fn"
            query="""
            (function_item
            name: (identifier) @name) @fn"""
            range_capture=["fn"]
            identifier_capture=["name"]
        "#,
        )
        .unwrap();
        let source = b"
fn main() {
    fn inner_main() {
        fn inner_inner_main() {

        }
    
        fn inner_inner_main_2() {

        }
    }
}

        ";

        let matches = pattern.matches(source, None, None).unwrap();

        let main = Rc::new(PatternMatch {
            hidden: false,
            kind: "fn".into(),
            qualifiers: vec!["main".into()],
            full_qualifiers: vec!["main".into()],
            parent: None,
            ranges: RefCell::new(vec![tree_sitter::Range {
                start_byte: 1,
                end_byte: 135,
                start_point: tree_sitter::Point { row: 1, column: 0 },
                end_point: tree_sitter::Point { row: 11, column: 1 },
            }]),
        });

        let inner_main = Rc::new(PatternMatch {
            hidden: false,
            kind: "fn".into(),
            qualifiers: vec!["inner_main".into()],
            full_qualifiers: vec!["main".into(), "inner_main".into()],
            parent: Some(main.clone()),
            ranges: RefCell::new(vec![tree_sitter::Range {
                start_byte: 17,
                end_byte: 133,
                start_point: tree_sitter::Point { row: 2, column: 4 },
                end_point: tree_sitter::Point { row: 10, column: 5 },
            }]),
        });
        let inner_inner_main = Rc::new(PatternMatch {
            hidden: false,
            kind: "fn".into(),
            qualifiers: vec!["inner_inner_main".into()],
            full_qualifiers: vec![
                "main".into(),
                "inner_main".into(),
                "inner_inner_main".into(),
            ],
            parent: Some(inner_main.clone()),
            ranges: RefCell::new(vec![tree_sitter::Range {
                start_byte: 43,
                end_byte: 77,
                start_point: tree_sitter::Point { row: 3, column: 8 },
                end_point: tree_sitter::Point { row: 5, column: 9 },
            }]),
        });
        let inner_inner_main_2 = Rc::new(PatternMatch {
            hidden: false,
            kind: "fn".into(),
            qualifiers: vec!["inner_inner_main_2".into()],
            full_qualifiers: vec![
                "main".into(),
                "inner_main".into(),
                "inner_inner_main_2".into(),
            ],
            parent: Some(inner_main.clone()),
            ranges: RefCell::new(vec![tree_sitter::Range {
                start_byte: 91,
                end_byte: 127,
                start_point: tree_sitter::Point { row: 7, column: 8 },
                end_point: tree_sitter::Point { row: 9, column: 9 },
            }]),
        });

        assert_eq!(
            vec![main, inner_main, inner_inner_main, inner_inner_main_2],
            matches
        );
    }

    #[test]
    fn matches_with_multiple_ranges() {
        let pattern = create_pattern(
            r#"
            parser = { precompiled = "rust" }
            file = { file_types = ["rs"], exact_file_name = ["package.json"] }
            [[pattern]]
            kind="fn"
            query="""
            (function_item
            name: (identifier) @name) @fn"""
            range_capture=["fn"]
            identifier_capture=["name"]
            [[pattern]]
            kind="impl"
            query="""
            (impl_item
            type: (_) @name 
            !trait) @impl"""
            range_capture=["impl"]
            identifier_capture=["name"]
        "#,
        )
        .unwrap();
        let source = b"
impl Foo {

}

impl Bar {

}

impl Foo {
    fn baz() {

    }
}

impl Foo {

}";
        let impl_foo = Rc::new(PatternMatch {
            hidden: false,
            kind: "impl".into(),
            qualifiers: vec!["Foo".into()],
            full_qualifiers: vec!["Foo".into()],
            parent: None,
            ranges: RefCell::new(vec![
                tree_sitter::Range {
                    start_byte: 1,
                    end_byte: 14,
                    start_point: tree_sitter::Point { row: 1, column: 0 },
                    end_point: tree_sitter::Point { row: 3, column: 1 },
                },
                tree_sitter::Range {
                    start_byte: 31,
                    end_byte: 65,
                    start_point: tree_sitter::Point { row: 9, column: 0 },
                    end_point: tree_sitter::Point { row: 13, column: 1 },
                },
                tree_sitter::Range {
                    start_byte: 67,
                    end_byte: 80,
                    start_point: tree_sitter::Point { row: 15, column: 0 },
                    end_point: tree_sitter::Point { row: 17, column: 1 },
                },
            ]),
        });

        let impl_bar = Rc::new(PatternMatch {
            hidden: false,
            kind: "impl".into(),
            qualifiers: vec!["Bar".into()],
            full_qualifiers: vec!["Bar".into()],
            parent: None,
            ranges: RefCell::new(vec![tree_sitter::Range {
                start_byte: 16,
                end_byte: 29,
                start_point: tree_sitter::Point { row: 5, column: 0 },
                end_point: tree_sitter::Point { row: 7, column: 1 },
            }]),
        });

        let impl_foo_baz = Rc::new(PatternMatch {
            hidden: false,
            kind: "fn".into(),
            qualifiers: vec!["baz".into()],
            full_qualifiers: vec!["Foo".into(), "baz".into()],
            parent: Some(impl_foo.clone()),
            ranges: RefCell::new(vec![tree_sitter::Range {
                start_byte: 46,
                end_byte: 63,
                start_point: tree_sitter::Point { row: 10, column: 4 },
                end_point: tree_sitter::Point { row: 12, column: 5 },
            }]),
        });

        let matches = pattern.matches(source, None, None).unwrap();

        assert_eq!(vec![impl_foo, impl_bar, impl_foo_baz], matches);
    }
}
