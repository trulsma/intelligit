use anyhow::Context;
use gix::features::hash::Sha1Digest;
use libloading::{Library, Symbol};
use std::io::Write;
use std::{
    collections::HashMap,
    hash::Hash,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(serde::Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
#[serde(untagged)]
#[allow(dead_code)]
pub enum TSParser {
    Remote {
        url: String,
        rev: Option<String>,
        /// If the grammar json is not in src/, it must be specified. It is the case when more than
        /// 1 language is stored in the same repo.
        src_path: Option<String>,
    },
    Local {
        path: String,
        /// The src path if the source is not /src. E.g when multiple languages is in same repo
        src_path: Option<String>,
    },

    /// Precompiled parser are included in the binary to avoid needing to compile parser when only
    /// using core patterns
    Precompiled { precompiled: String },
}

impl TSParser {
    // TODO: need to have multiple hashes. One for source and one for compiled version. This is
    // needed cause the source can be same for multiple parser. e.g OCaml repo contains both .ml and
    // .mli. We should avoid cloning multiple times..
    fn hash(&self) -> Sha1Digest {
        let bytes = match self {
            Self::Remote { url, .. } => url.as_bytes(),
            Self::Local { path, .. } => path.as_bytes(),
            Self::Precompiled { precompiled } => precompiled.as_bytes(),
        };
        let suffix_bytes = match self {
            Self::Remote { src_path, .. } => src_path.as_ref(),
            Self::Local { src_path, .. } => src_path.as_ref(),
            Self::Precompiled { .. } => None,
        }
        .map(|grammar_json| grammar_json.as_bytes())
        .unwrap_or(&[]);
        let mut hasher = gix::features::hash::hasher(gix::hash::Kind::Sha1);
        hasher.update(bytes);
        hasher.update(suffix_bytes);

        hasher.digest()
    }
}

fn sha1_to_hex(sha1: Sha1Digest) -> String {
    let sha1 = gix::ObjectId::Sha1(sha1);
    let hex = sha1.to_hex();
    let hex = format!("{hex}");
    hex
}

// This causes some issues.. tree-sitter sees 2 constants but really just one exist.. Same problem
// as multiple impl's. Could also create some specific pattern for this so cfg becomes part of
// qualifiers
#[cfg(unix)]
const DYLIB_EXTENSION: &str = "so";

#[cfg(windows)]
const DYLIB_EXTENSION: &str = "dll";

const BUILD_TARGET: &str = env!("BUILD_TARGET");

#[allow(dead_code)]
pub struct TSLanguageProviderConfig {
    allow_compile: bool,
    compile_debug: bool,
    allow_clone: bool,
    force_recompile: bool,
}
impl Default for TSLanguageProviderConfig {
    fn default() -> Self {
        Self {
            allow_compile: true,
            allow_clone: true,
            force_recompile: false,
            compile_debug: false,
        }
    }
}

pub struct TSLanguageProvider {
    parser_path: PathBuf,
    languages: HashMap<TSParser, tree_sitter::Language>,
    config: TSLanguageProviderConfig,
}

impl TSLanguageProvider {
    pub fn from_parser_path(parser_path: PathBuf) -> Self {
        Self {
            parser_path,
            languages: HashMap::default(),
            config: Default::default(),
        }
    }

    pub fn language_for_parser(&self, parser: &TSParser) -> Option<tree_sitter::Language> {
        self.languages.get(parser).copied()
    }

    fn clone(&mut self, raw_url: &str, target: &Path) -> anyhow::Result<()> {
        let url = gix::url::parse(gix::bstr::BStr::new(raw_url.as_bytes()))
            .context("Url was not valid")?;

        // TODO: handle partially cloned directories.. like ctrl-c when cloning
        std::fs::create_dir_all(target).context("Failed to create target directory")?;

        let mut prepare_clone =
            gix::prepare_clone(url, target).context("Failed to prepare clone")?;
        log::info!("Cloning {raw_url:?} into {target:?}...");
        let (mut prepare_checkout, _) = prepare_clone
            .fetch_then_checkout(
                gix::progress::DoOrDiscard::from(Some(gix::progress::Discard)),
                &gix::interrupt::IS_INTERRUPTED,
            )
            .context("Failed to fetch and checkout repository")?;

        let (repo, _) = prepare_checkout
            .main_worktree(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
            .context("Failed to get main worktree from cloned repository")?;
        log::info!(
            "Repo cloned into {:?}",
            repo.work_dir().expect("directory pre-created")
        );

        Ok(())
    }

    fn get_precompiled_parser(&mut self, name: &str) -> anyhow::Result<tree_sitter::Language> {
        let language = match name {
            "rust" => Ok(tree_sitter_rust::language()),
            "c#" | "c-sharp" | "csharp" =>  Ok(tree_sitter_c_sharp::language()),
            "json" =>  Ok(tree_sitter_json::language()),
            "toml" =>  Ok(tree_sitter_toml::language()),
            "ocaml" =>  Ok(tree_sitter_ocaml::language_ocaml()),
            "ocaml_interface" =>  Ok(tree_sitter_ocaml::language_ocaml_interface()),
            "go" =>  Ok(tree_sitter_go::language()),
            name => anyhow::bail!("\"{}\" is not a precompiled parser. Make sure it is spelled correctly and is contained in the list of precompiled parser", name)
        };

        if let Ok(lang) = language {
            log::info!("Using precompiled parser {}", name);
            self.languages.insert(
                TSParser::Precompiled {
                    precompiled: name.to_owned(),
                },
                lang,
            );
        }

        language
    }

    pub fn create_language_for_parser(
        &mut self,
        parser: &TSParser,
    ) -> anyhow::Result<tree_sitter::Language> {
        let source_path = match parser {
            TSParser::Precompiled { precompiled } => {
                return self.get_precompiled_parser(precompiled)
            }
            TSParser::Local { path, .. } => PathBuf::from(path),
            TSParser::Remote { url, .. } => {
                let hash = sha1_to_hex(parser.hash());
                let path = self.parser_path.join("source").join(hash);

                if self.config.allow_clone && !path.is_dir() && !path.exists() {
                    self.clone(url, &path).context("Failed to clone repo")?;
                }

                path
            }
        };

        let src_path = match parser {
            TSParser::Local {
                src_path: Some(path),
                ..
            } => source_path.join(path),
            TSParser::Remote {
                src_path: Some(path),
                ..
            } => source_path.join(path),
            _ => source_path.join("src"),
        };

        let grammar_path = src_path.join("grammar.json");

        #[derive(serde::Deserialize)]
        struct GrammarJSON {
            name: String,
        }
        let mut grammar_file = std::fs::File::open(grammar_path)
            .context("Failed to read grammar.json from parser source")?;
        let grammar_json: GrammarJSON =
            serde_json::from_reader(std::io::BufReader::new(&mut grammar_file))
                .context("Failed parse grammar.json from parser source")?;

        let hashed = sha1_to_hex(parser.hash());
        let library_dir = self.parser_path.join("compiled").join(hashed);
        let mut library = library_dir.join(&grammar_json.name);
        library.set_extension(DYLIB_EXTENSION);

        if !library.exists() {
            let header_path = src_path.clone();
            let parser_path = src_path.join("parser.c");
            let mut scanner_path = src_path.join("scanner.c");
            let scanner_path = if scanner_path.exists() {
                Some(scanner_path)
            } else {
                scanner_path.set_extension("cc");
                if scanner_path.exists() {
                    Some(scanner_path)
                } else {
                    None
                }
            };
            std::fs::create_dir_all(&library_dir).context("Failed to create output directory")?;

            let mut config = cc::Build::new();
            config
                .cpp(true)
                .opt_level(2)
                .cargo_metadata(false)
                .target(BUILD_TARGET)
                .host(BUILD_TARGET);

            let compiler = config.get_compiler();
            let mut command = Command::new(compiler.path());
            for (key, value) in compiler.env() {
                command.env(key, value);
            }

            if cfg!(windows) {
                command.args(["/nologo", "/LD", "/I"]).arg(header_path);
                if self.config.compile_debug {
                    command.arg("/Od");
                } else {
                    command.arg("/O2");
                }
                command.arg(parser_path);
                if let Some(scanner_path) = scanner_path.as_ref() {
                    command.arg(scanner_path);
                }
                command.arg("/link").arg(format!(
                    "/out:{}",
                    library_dir.to_str().context("Invalid library directory")?
                ));
            } else {
                command
                    .arg("-shared")
                    .arg("-fPIC")
                    .arg("-fno-exceptions")
                    .arg("-g")
                    .arg("-I")
                    .arg(header_path)
                    .arg("-o")
                    .arg(&library);

                if self.config.compile_debug {
                    command.arg("-O0");
                } else {
                    command.arg("-O2");
                }

                if let Some(scanner_path) = scanner_path.as_ref() {
                    if scanner_path.extension() == Some("c".as_ref()) {
                        command.arg("-xc").arg("-std=c99").arg(scanner_path);
                    } else {
                        command.arg(scanner_path);
                    }
                }
                command.arg("-xc").arg(parser_path);
            }

            log::info!("Compiling {}..", source_path.display());
            let output = command.output().context("Failed to compile source..")?;

            if !output.status.success() {
                std::io::stdout()
                    .write_all(&output.stdout)
                    .expect("Can write to stdout");
                std::io::stderr()
                    .write_all(&output.stderr)
                    .expect("Can write to stderr");
                panic!();
            }
        }

        let library = unsafe { Library::new(&library) }
            .context("Failed to get library from compiled source")?;
        let language_fn_name = format!("tree_sitter_{}", grammar_json.name.replace('-', "_"));
        let language = unsafe {
            let language_fn: Symbol<unsafe extern "C" fn() -> tree_sitter::Language> = library
                .get(language_fn_name.as_bytes())
                .context("Failed to load symbols from compiled library")?;

            language_fn()
        };
        log::info!("Loaded {}", language_fn_name);
        std::mem::forget(library);

        self.languages.insert(parser.clone(), language);

        Ok(language)
    }
}
