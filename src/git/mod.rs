use gix::bstr::{BStr, BString, ByteSlice};
use gix::env::os_str_to_bstring;
use gix::index::entry::{Flags, Mode, Stat};
use gix::ObjectId;
pub use gix::{open, Repository};
use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::path::Path;

pub trait RepositoryExt {
    /// Get an iterator over all files in the file system
    fn untracked_entries(&self) -> Option<FileEntryList>;
    /// Get an iterator over all files in the index
    fn staged_entries(&self) -> Option<IndexEntryList<'_>>;
    /// Get an iterator over all files in the commit
    fn commit_entries(&self, commit: &gix::Commit) -> Option<TreeEntryList<'_>>;
    /// Get an iterator with all the changes in the commits compared with its first parent (or empty
    /// tree for first commit)
    fn changes_in_history<'repo>(
        &'repo self,
        start: gix::Commit<'repo>,
    ) -> ChangeHistoryIterator<'repo>;

    fn find_object_by_partial_hash<S: AsRef<str>>(&self, hex: S)
        -> anyhow::Result<gix::Object<'_>>;
}

pub trait CommitExt {
    /// Get first parent or none
    fn parent(&self) -> Option<Self>
    where
        Self: Sized;
}

impl<'repo> CommitExt for gix::Commit<'repo> {
    fn parent(&self) -> Option<Self> {
        let parent_id = self.parent_ids().next()?;
        Some(parent_id.object().ok()?.into_commit())
    }
}

impl RepositoryExt for gix::Repository {
    fn untracked_entries(&self) -> Option<FileEntryList> {
        self.path().parent().map(FileEntryList::new)
    }

    fn staged_entries(&self) -> Option<IndexEntryList<'_>> {
        IndexEntryList::from_repository(self)
    }

    fn commit_entries(&self, commit: &gix::Commit) -> Option<TreeEntryList<'_>> {
        commit
            .tree()
            .ok()
            .map(|tree| TreeEntryList::new(self, tree))
    }

    fn changes_in_history<'repo>(
        &'repo self,
        start: gix::Commit<'repo>,
    ) -> ChangeHistoryIterator<'repo> {
        ChangeHistoryIterator {
            repo: self,
            commit: Some(start),
        }
    }

    fn find_object_by_partial_hash<S: AsRef<str>>(
        &self,
        hex: S,
    ) -> anyhow::Result<gix::Object<'_>> {
        let hex = hex.as_ref();
        let prefix = gix::index::hash::Prefix::from_hex(hex)?;

        let id = match self.objects.lookup_prefix(prefix, None) {
            Ok(Some(Ok(id))) => id,
            Ok(Some(Err(()))) => anyhow::bail!("Found more than one object matching {}", hex),
            Ok(None) => anyhow::bail!("Found no objects matching {}", hex),
            Err(e) => return Err(e.into()),
        };
        let object = self.find_object(id)?;

        Ok(object)
    }
}

/// Simplified version of [gix::object::tree::diff::Change] without rewrite and simplified lifetime
#[derive(Debug, Clone)]
pub struct Change<'repo> {
    pub location: BString,
    pub event: Event<'repo>,
}

/// Simplified version of [gix::object::tree::diff::change::Event] without rewrite and simplified
/// lifetime
#[derive(Debug, Clone)]
pub enum Event<'repo> {
    Addition {
        entry_mode: gix::objs::tree::EntryMode,
        id: gix::Id<'repo>,
    },
    Deletion {
        entry_mode: gix::objs::tree::EntryMode,
        id: gix::Id<'repo>,
    },
    Modification {
        previous_entry_mode: gix::objs::tree::EntryMode,
        previous_id: gix::Id<'repo>,
        entry_mode: gix::objs::tree::EntryMode,
        id: gix::Id<'repo>,
    },
}

impl<'a, 'repo> From<gix::object::tree::diff::Change<'a, 'repo, 'repo>> for Change<'repo> {
    fn from(value: gix::object::tree::diff::Change<'a, 'repo, 'repo>) -> Self {
        use gix::object::tree::diff::change as gix;
        Self {
            location: value.location.to_owned(),
            event: match value.event {
                gix::Event::Addition { entry_mode, id } => Event::Addition { entry_mode, id },
                gix::Event::Deletion { entry_mode, id } => Event::Deletion { entry_mode, id },
                gix::Event::Modification {
                    previous_entry_mode,
                    previous_id,
                    entry_mode,
                    id,
                } => Event::Modification {
                    previous_entry_mode,
                    previous_id,
                    entry_mode,
                    id,
                },
                gix::Event::Rewrite { .. } => {
                    unreachable!("track_rewrites(None) turns off Rewrites")
                }
            },
        }
    }
}

/// Iterator of changes between commit and parent (empty tree if no parent)
pub struct ChangeHistoryIterator<'repo> {
    repo: &'repo Repository,
    commit: Option<gix::Commit<'repo>>,
}

impl<'repo> ChangeHistoryIterator<'repo> {
    /// Returns an empty change history iterator
    pub fn new_empty(repo: &'repo Repository) -> ChangeHistoryIterator {
        Self { repo, commit: None }
    }
}

impl<'repo> Iterator for ChangeHistoryIterator<'repo> {
    type Item = (gix::Commit<'repo>, Vec<Change<'repo>>);

    fn next(&mut self) -> Option<Self::Item> {
        let commit = self.commit.take()?;
        let parent_id = commit.parent_ids().next();
        let tree = commit.tree().ok()?;

        let (parent_commit, parent_tree) = if let Some(parent_id) = parent_id {
            let parent_commit = parent_id.object().ok()?.into_commit();
            let parent_tree = parent_commit.tree().ok()?;

            (Some(parent_commit), parent_tree)
        } else {
            (None, self.repo.empty_tree())
        };

        let mut changes = vec![];
        parent_tree
            .changes()
            .ok()?
            .track_path()
            .track_rewrites(None)
            .for_each_to_obtain_tree(
                &tree,
                |change| -> Result<gix::object::tree::diff::Action, Infallible> {
                    if change.event.entry_mode() == gix::objs::tree::EntryMode::Blob {
                        changes.push(Change::from(change));
                    }
                    Ok(gix::object::tree::diff::Action::Continue)
                },
            )
            .ok()?;

        self.commit = parent_commit;

        Some((commit, changes))
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct IndexEntry<'a> {
    oid: ObjectId,
    stat: Stat,
    flags: Flags,
    mode: Mode,
    path: BString,
    repo: &'a Repository,
}

impl<'a> Entry for IndexEntry<'a> {
    fn path(&self) -> &BStr {
        self.path.as_bstr()
    }
    fn modification_time(&self) -> Option<gix::index::entry::stat::Time> {
        Some(self.stat.mtime)
    }
    fn content_hash(&self) -> Option<ObjectId> {
        Some(self.oid)
    }

    fn content(&self) -> Vec<u8> {
        self.repo.find_object(self.oid).unwrap().data.clone()
    }
}

#[derive(Debug)]
pub struct FileEntry {
    stat: Stat,
    path: BString,
}

impl Entry for FileEntry {
    fn path(&self) -> &BStr {
        self.path.as_bstr()
    }

    fn modification_time(&self) -> Option<gix::index::entry::stat::Time> {
        Some(self.stat.mtime)
    }

    fn content_hash(&self) -> Option<ObjectId> {
        let buf = std::fs::read(self.path.to_string()).unwrap();
        Some(gix::objs::compute_hash(
            gix::hash::Kind::Sha1,
            gix::objs::Kind::Blob,
            buf.as_slice(),
        ))
    }

    fn content(&self) -> Vec<u8> {
        std::fs::read(self.path.to_string()).unwrap()
    }
}

#[derive(Debug)]
pub struct TreeEntry<'a> {
    path: BString,
    oid: ObjectId,
    repo: &'a Repository,
}

impl<'a> Entry for TreeEntry<'a> {
    fn path(&self) -> &BStr {
        self.path.as_bstr()
    }

    fn content_hash(&self) -> Option<ObjectId> {
        Some(self.oid)
    }

    fn content(&self) -> Vec<u8> {
        self.repo.find_object(self.oid).unwrap().data.clone()
    }
}

pub enum EntryDiff {
    Changed,
    MaybeChanged,
    NoChange,
}

pub trait Entry {
    fn path(&self) -> &BStr;

    fn content(&self) -> Vec<u8>;

    fn content_hash(&self) -> Option<ObjectId> {
        None
    }

    fn modification_time(&self) -> Option<gix::index::entry::stat::Time> {
        None
    }

    fn diff(&self, other: &impl Entry) -> EntryDiff {
        match (self.modification_time(), other.modification_time()) {
            (Some(lhs), Some(rhs)) if lhs == rhs => return EntryDiff::NoChange,
            _ => {}
        };

        match (self.content_hash(), other.content_hash()) {
            (Some(lhs), Some(rhs)) if lhs == rhs => return EntryDiff::NoChange,
            (Some(_), Some(_)) => return EntryDiff::Changed,
            _ => {}
        };

        EntryDiff::MaybeChanged
    }
}

// Make lazy and make modification time also work for directories
pub trait EntryList {
    type Item: Entry;

    fn keys(&self) -> HashSet<&BStr> {
        self.entries().keys().map(|s| s.as_bstr()).collect()
    }

    fn entries(&self) -> &HashMap<BString, Self::Item>;
}

#[derive(Default)]
pub struct FileEntryList {
    entries: HashMap<BString, FileEntry>,
}

impl FileEntryList {
    fn new(root: &Path) -> Self {
        let mut builder = ignore::WalkBuilder::new(root);
        builder.hidden(false);
        builder.filter_entry(|p| !p.path().starts_with("./.git/"));

        let entries = builder
            .build()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().map(|ft| ft.is_file()).unwrap_or(false))
            .map(move |entry| {
                let path = entry.path().strip_prefix(root).unwrap().as_os_str();
                let path = os_str_to_bstring(path).unwrap();

                (
                    path.clone(),
                    FileEntry {
                        stat: Stat::from_fs(&std::fs::metadata(entry.path()).unwrap()).unwrap(),
                        path,
                    },
                )
            })
            .collect();

        Self { entries }
    }
}

impl EntryList for FileEntryList {
    type Item = FileEntry;

    fn entries(&self) -> &HashMap<BString, Self::Item> {
        &self.entries
    }
}

pub struct IndexEntryList<'a> {
    entries: HashMap<BString, IndexEntry<'a>>,
}

impl<'a> IndexEntryList<'a> {
    pub fn new_empty() -> Self {
        IndexEntryList { entries: HashMap::new() }
    }

    fn from_repository(repo: &'a gix::Repository) -> Option<Self> {
        let index = repo.index().ok()?;
        let index_clone = index.clone();
        let entries = index
            .entries()
            .iter()
            .filter(|entry| entry.mode == gix::index::entry::Mode::FILE)
            .map(move |entry| {
                let path = entry.path(&index_clone).to_vec();
                let path = BString::new(path);
                (
                    path.clone(),
                    IndexEntry {
                        oid: entry.id,
                        stat: entry.stat,
                        flags: entry.flags,
                        mode: entry.mode,
                        path,
                        repo,
                    },
                )
            })
            .collect();

        Some(Self { entries })
    }
}

impl<'a> EntryList for IndexEntryList<'a> {
    type Item = IndexEntry<'a>;

    fn entries(&self) -> &HashMap<BString, Self::Item> {
        &self.entries
    }
}

pub struct TreeEntryList<'a> {
    entries: HashMap<BString, TreeEntry<'a>>,
}

impl<'a> TreeEntryList<'a> {
    pub fn new_empty() -> Self {
        TreeEntryList { entries: HashMap::new() }
    }

    fn new(repo: &'a gix::Repository, tree: gix::Tree) -> Self {
        let mut recorder = gix::traverse::tree::Recorder::default();

        tree.traverse()
            .breadthfirst(&mut recorder)
            .expect("Tree is valid");

        Self {
            entries: recorder
                .records
                .into_iter()
                .filter(|entry| entry.mode == gix::objs::tree::EntryMode::Blob)
                .map(|entry| {
                    (
                        entry.filepath.clone(),
                        TreeEntry {
                            oid: entry.oid,
                            path: entry.filepath,
                            repo,
                        },
                    )
                })
                .collect(),
        }
    }
}

impl<'a> EntryList for TreeEntryList<'a> {
    type Item = TreeEntry<'a>;

    fn entries(&self) -> &HashMap<BString, Self::Item> {
        &self.entries
    }
}

#[derive(Debug)]
pub enum DiffResult {
    Added {
        path: String,
        content: Vec<u8>,
    },
    Deleted {
        path: String,
        content: Vec<u8>,
    },
    Modified {
        path: String,
        before_content: Vec<u8>,
        after_content: Vec<u8>,
    },
}

pub struct EntryListDiff<'a, T: EntryList, U: EntryList> {
    before: &'a T,
    after: &'a U,
    keys: std::collections::hash_set::IntoIter<&'a BStr>,
}

impl<'a, T: EntryList, U: EntryList> EntryListDiff<'a, T, U> {
    fn new(before: &'a T, after: &'a U) -> Self {
        let mut keys = before.keys().clone();
        keys.extend(after.keys());
        let keys = keys.into_iter();
        Self {
            before,
            after,
            keys,
        }
    }
}

impl<'a, T: EntryList, U: EntryList> Iterator for EntryListDiff<'a, T, U> {
    type Item = DiffResult;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let key = self.keys.next()?;
            return match (
                self.before.entries().get(key),
                self.after.entries().get(key),
            ) {
                (Some(before_entry), Some(after_entry)) => match before_entry.diff(after_entry) {
                    EntryDiff::MaybeChanged => Some(DiffResult::Modified {
                        path: before_entry.path().to_string(),
                        before_content: before_entry.content(),
                        after_content: after_entry.content(),
                    }),
                    EntryDiff::Changed => Some(DiffResult::Modified {
                        path: before_entry.path().to_string(),
                        before_content: before_entry.content(),
                        after_content: after_entry.content(),
                    }),
                    EntryDiff::NoChange => continue,
                },
                (Some(before_entry), None) => Some(DiffResult::Deleted {
                    path: before_entry.path().to_string(),
                    content: before_entry.content(),
                }),
                (None, Some(after_entry)) => Some(DiffResult::Added {
                    path: after_entry.path().to_string(),
                    content: after_entry.content(),
                }),
                (None, None) => {
                    unreachable!()
                }
            };
        }
    }
}

pub fn diff<'a, T: EntryList, U: EntryList>(
    before: &'a T,
    after: &'a U,
) -> EntryListDiff<'a, T, U> {
    EntryListDiff::new(before, after)
}
