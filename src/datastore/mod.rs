use rusqlite::{params_from_iter, Connection, OptionalExtension};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Commit {
    pub id: Vec<u8>,
    pub seconds_since_epoch: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Symbol {
    pub kind: String,
    pub qualifiers: String,
    pub file_path: String,
    // need to add pattern hash
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Change {
    pub commit: Commit,
    pub symbol: Symbol,
    pub novel_lhs: u32,
    pub novel_rhs: u32,
    pub size_after: u64,
}

fn setup(conn: &Connection) -> anyhow::Result<()> {
    conn.execute(
        "create table if not exists changes (
            commit_id blob not null, 
            seconds_since_epoch int not null,
            kind text not null,
            qualifiers text not null,
            file_path text not null,
            novel_lhs int not null,
            novel_rhs int not null,
            size_after int not null,
            primary key (commit_id, kind, qualifiers, file_path)
        )",
        (),
    )?;

    Ok(())
}

pub fn insert_changes(
    conn: &mut Connection,
    changes: impl Iterator<Item = Change>,
) -> anyhow::Result<()> {
    let tx = conn.transaction()?;
    for change in changes {
        tx.execute(
            "insert into changes (
                commit_id, 
                seconds_since_epoch, 
                kind, 
                qualifiers, 
                file_path, 
                novel_lhs, 
                novel_rhs, 
                size_after
            ) 
            values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            (
                change.commit.id,
                change.commit.seconds_since_epoch,
                change.symbol.kind,
                change.symbol.qualifiers,
                change.symbol.file_path,
                change.novel_lhs,
                change.novel_rhs,
                change.size_after,
            ),
        )?;
    }
    tx.commit()?;

    Ok(())
}

pub fn purge(conn: &Connection) -> anyhow::Result<()> {
    conn.execute("delete from changes", ())?;

    Ok(())
}

pub fn latest_commit(conn: &Connection) -> anyhow::Result<Option<Commit>> {
    Ok(conn.query_row(
        "select commit_id, seconds_since_epoch from changes order by seconds_since_epoch desc limit 1",
        [],
        |row| {
            Ok(Commit {
                id: row.get(0)?,
                seconds_since_epoch: row.get(1)?,
            })
        },
    )
    .optional()?)
}

pub fn earliest_commit(conn: &Connection) -> anyhow::Result<Option<Commit>> {
    Ok(conn.query_row(
        "select commit_id, seconds_since_epoch from changes order by seconds_since_epoch limit 1",
        [],
        |row| {
            Ok(Commit {
                id: row.get(0)?,
                seconds_since_epoch: row.get(1)?,
            })
        },
    )
    .optional()?)
}

pub fn symbol_commits(conn: &Connection, symbol: &Symbol) -> anyhow::Result<Vec<Commit>> {
    let mut stmt = conn.prepare("select distinct commit_id, seconds_since_epoch from changes where kind = ?1 and qualifiers = ?2 and file_path = ?3")?;

    let commits = stmt
        .query_map(
            (&symbol.kind, &symbol.qualifiers, &symbol.file_path),
            |row| {
                Ok(Commit {
                    id: row.get(0)?,
                    seconds_since_epoch: row.get(1)?,
                })
            },
        )?
        .flatten();

    Ok(commits.collect())
}

pub fn all_commits(conn: &Connection) -> anyhow::Result<Vec<Commit>> {
    let mut stmt = conn.prepare("select distinct commit_id, seconds_since_epoch from changes")?;

    let commits = stmt
        .query_map((), |row| {
            Ok(Commit {
                id: row.get(0)?,
                seconds_since_epoch: row.get(1)?,
            })
        })?
        .flatten();

    Ok(commits.collect())
}

#[allow(dead_code)]
pub fn changes_for_symbol(conn: &Connection, symbol: &Symbol) -> anyhow::Result<Vec<Change>> {
    let mut stmt = conn.prepare("select commit_id, seconds_since_epoch, kind, qualifiers, file_path, novel_lhs, novel_rhs, size_after from changes where kind = ?1 and file_path = ?2 and qualifiers = ?3")?;

    let query = stmt.query_map(
        (&symbol.kind, &symbol.file_path, &symbol.qualifiers),
        |row| {
            Ok(Change {
                commit: Commit {
                    id: row.get(0)?,
                    seconds_since_epoch: row.get(1)?,
                },
                symbol: Symbol {
                    kind: row.get(2)?,
                    qualifiers: row.get(3)?,
                    file_path: row.get(4)?,
                },
                novel_lhs: row.get(5)?,
                novel_rhs: row.get(6)?,
                size_after: row.get(7)?,
            })
        },
    )?;

    Ok(query.flatten().collect())
}

pub fn query_symbols(
    conn: &Connection,
    file: Option<&str>,
    kind: Option<&str>,
    qualifiers: Option<&str>,
) -> anyhow::Result<Vec<Symbol>> {
    let query = r#"
    select distinct file_path, kind, qualifiers from changes 
    where 
        (file_path = ?1 or ?1 is null) and 
        (kind = ?2 or ?2 is null) and 
        (qualifiers = ?3 or ?3 is null)"#
        .to_owned();

    let mut stmt = conn.prepare(&query)?;

    let params = params_from_iter([file, kind, qualifiers]);

    let query = stmt.query_map(params, |row| {
        Ok(Symbol {
            file_path: row.get(0)?,
            kind: row.get(1)?,
            qualifiers: row.get(2)?,
        })
    })?;

    Ok(query.flatten().collect())
}

pub fn query_changes(conn: &Connection) -> anyhow::Result<Vec<Change>> {
    let mut stmt = conn.prepare("select commit_id, seconds_since_epoch, kind, qualifiers, file_path, novel_lhs, novel_rhs, size_after from changes")?;

    let query = stmt.query_map([], |row| {
        Ok(Change {
            commit: Commit {
                id: row.get(0)?,
                seconds_since_epoch: row.get(1)?,
            },
            symbol: Symbol {
                kind: row.get(2)?,
                qualifiers: row.get(3)?,
                file_path: row.get(4)?,
            },
            novel_lhs: row.get(5)?,
            novel_rhs: row.get(6)?,
            size_after: row.get(7)?,
        })
    })?;

    Ok(query.flatten().collect())
}

pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Connection> {
    let path = path.as_ref();

    if !path.exists() {
        std::fs::create_dir_all(path)?;
    }

    let path = if path.is_dir() {
        path.join("objects.db")
    } else {
        path.into()
    };

    let conn = Connection::open(path)?;

    setup(&conn)?;

    Ok(conn)
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use crate::datastore::query_symbols;

    use super::{
        all_commits, earliest_commit, insert_changes, latest_commit, open, query_changes,
        symbol_commits, Change, Commit, Symbol,
    };

    fn assert_eq_items<T: Eq + std::fmt::Debug>(
        a: impl IntoIterator<Item = T>,
        b: impl IntoIterator<Item = T>,
    ) {
        let a = a.into_iter().collect_vec();
        let b = b.into_iter().collect_vec();

        for item in a.iter() {
            assert!(b.iter().contains(item));
        }
        for item in b.iter() {
            assert!(a.iter().contains(item));
        }
    }

    #[test]
    fn insert_and_query_returns_same() {
        let dir = tempfile::TempDir::new().unwrap();

        let mut conn = open(&dir).unwrap();

        let changes = vec![Change {
            commit: Commit {
                id: vec![1, 2, 3, 4],
                seconds_since_epoch: 12345156123i64,
            },
            symbol: Symbol {
                file_path: "main.rs".into(),
                kind: "fn".into(),
                qualifiers: "main".into(),
            },
            novel_lhs: 10,
            novel_rhs: 8,
            size_after: 22,
        }];
        insert_changes(&mut conn, changes.clone().into_iter()).unwrap();

        let queried_changes = query_changes(&conn).unwrap();

        assert_eq!(queried_changes, changes);
    }

    #[test]
    fn query_symbols_returns_correct() {
        let dir = tempfile::TempDir::new().unwrap();

        let mut conn = open(&dir).unwrap();

        let symbols = [
            Symbol {
                file_path: "main.rs".into(),
                kind: "fn".into(),
                qualifiers: "main".into(),
            },
            Symbol {
                file_path: "main.rs".into(),
                kind: "struct".into(),
                qualifiers: "Args".into(),
            },
            Symbol {
                file_path: "main.rs".into(),
                kind: "fn".into(),
                qualifiers: "log".into(),
            },
            Symbol {
                file_path: "other_main.rs".into(),
                kind: "fn".into(),
                qualifiers: "main".into(),
            },
            Symbol {
                file_path: "other_test.rs".into(),
                kind: "test".into(),
                qualifiers: "main".into(),
            },
        ];

        let fn_symbols = symbols
            .iter()
            .cloned()
            .filter(|symbol| symbol.kind == "fn")
            .collect_vec();
        let main_rs_symbols = symbols
            .iter()
            .cloned()
            .filter(|symbol| symbol.file_path == "main.rs")
            .collect_vec();
        let main_rs_fn_symbols = symbols
            .iter()
            .cloned()
            .filter(|symbol| symbol.file_path == "main.rs" && symbol.kind == "fn")
            .collect_vec();
        let main_qualifier_symbols = symbols
            .iter()
            .cloned()
            .filter(|symbol| symbol.qualifiers == "main")
            .collect_vec();
        let main_qualifier_fn_symbols = symbols
            .iter()
            .cloned()
            .filter(|symbol| symbol.qualifiers == "main" && symbol.kind == "fn")
            .collect_vec();
        let main_rs_qualifier_fn_symbols = symbols
            .iter()
            .cloned()
            .filter(|symbol| {
                symbol.qualifiers == "main" && symbol.kind == "fn" && symbol.file_path == "main.rs"
            })
            .collect_vec();

        let changes = symbols.iter().map(|symbol| Change {
            commit: Commit {
                id: vec![1, 2, 3, 4],
                seconds_since_epoch: 12345156123i64,
            },
            symbol: symbol.clone(),
            novel_lhs: 10,
            novel_rhs: 8,
            size_after: 22,
        });

        insert_changes(&mut conn, changes.clone()).unwrap();

        let queried_symbols = query_symbols(&conn, None, None, None).unwrap();
        let queried_fn_symbols = query_symbols(&conn, None, Some("fn"), None).unwrap();
        let queried_main_rs_symbols = query_symbols(&conn, Some("main.rs"), None, None).unwrap();
        let queried_main_rs_fn_symbols =
            query_symbols(&conn, Some("main.rs"), Some("fn"), None).unwrap();
        let queried_main_qualifier_symbols =
            query_symbols(&conn, None, None, Some("main")).unwrap();
        let queried_main_qualifier_fn_symbols =
            query_symbols(&conn, None, Some("fn"), Some("main")).unwrap();
        let queried_main_rs_qualifier_fn_symbols =
            query_symbols(&conn, Some("main.rs"), Some("fn"), Some("main")).unwrap();

        assert_eq_items(queried_symbols, symbols);
        assert_eq_items(queried_fn_symbols, fn_symbols);
        assert_eq_items(queried_main_rs_symbols, main_rs_symbols);
        assert_eq_items(queried_main_rs_fn_symbols, main_rs_fn_symbols);
        assert_eq_items(queried_main_qualifier_symbols, main_qualifier_symbols);
        assert_eq_items(queried_main_qualifier_fn_symbols, main_qualifier_fn_symbols);
        assert_eq_items(
            queried_main_rs_qualifier_fn_symbols,
            main_rs_qualifier_fn_symbols,
        );
    }

    #[test]
    fn last_and_first_commit() {
        let dir = tempfile::TempDir::new().unwrap();

        let mut conn = open(&dir).unwrap();

        let changes = vec![
            Change {
                commit: Commit {
                    id: vec![1, 2, 3, 4],
                    seconds_since_epoch: 10_000_000,
                },
                symbol: Symbol {
                    file_path: "main.rs".into(),
                    kind: "fn".into(),
                    qualifiers: "main".into(),
                },
                novel_lhs: 10,
                novel_rhs: 8,
                size_after: 22,
            },
            Change {
                commit: Commit {
                    id: vec![1, 2, 3, 4, 5],
                    seconds_since_epoch: 20_000_000,
                },
                symbol: Symbol {
                    file_path: "main.rs".into(),
                    kind: "fn".into(),
                    qualifiers: "main".into(),
                },
                novel_lhs: 10,
                novel_rhs: 8,
                size_after: 22,
            },
            Change {
                commit: Commit {
                    id: vec![1, 2, 3, 4, 5, 6],
                    seconds_since_epoch: 8_000_000,
                },
                symbol: Symbol {
                    file_path: "main.rs".into(),
                    kind: "fn".into(),
                    qualifiers: "main".into(),
                },
                novel_lhs: 10,
                novel_rhs: 8,
                size_after: 22,
            },
        ];

        insert_changes(&mut conn, changes.clone().into_iter()).unwrap();

        let last_commit = latest_commit(&conn).unwrap().unwrap();
        let first_commit = earliest_commit(&conn).unwrap().unwrap();

        assert_eq!(last_commit, changes[1].commit);
        assert_eq!(first_commit, changes[2].commit);
    }

    #[test]
    fn fetching_commits() {
        let dir = tempfile::TempDir::new().unwrap();

        let mut conn = open(&dir).unwrap();

        let changes = vec![
            Change {
                commit: Commit {
                    id: vec![1, 2, 3, 4],
                    seconds_since_epoch: 10_000_000,
                },
                symbol: Symbol {
                    file_path: "main.rs".into(),
                    kind: "fn".into(),
                    qualifiers: "main".into(),
                },
                novel_lhs: 10,
                novel_rhs: 8,
                size_after: 22,
            },
            Change {
                commit: Commit {
                    id: vec![1, 2, 3, 4, 5],
                    seconds_since_epoch: 20_000_000,
                },
                symbol: Symbol {
                    file_path: "main.rs".into(),
                    kind: "fn".into(),
                    qualifiers: "main".into(),
                },
                novel_lhs: 10,
                novel_rhs: 5,
                size_after: 22,
            },
            Change {
                commit: Commit {
                    id: vec![1, 2, 3, 4, 5],
                    seconds_since_epoch: 20_000_000,
                },
                symbol: Symbol {
                    file_path: "main.rs".into(),
                    kind: "fn".into(),
                    qualifiers: "test".into(),
                },
                novel_lhs: 10,
                novel_rhs: 8,
                size_after: 22,
            },
            Change {
                commit: Commit {
                    id: vec![1, 2, 3, 4, 5, 6],
                    seconds_since_epoch: 21_000_000,
                },
                symbol: Symbol {
                    file_path: "main.rs".into(),
                    kind: "fn".into(),
                    qualifiers: "test".into(),
                },
                novel_lhs: 10,
                novel_rhs: 8,
                size_after: 22,
            },
        ];

        insert_changes(&mut conn, changes.clone().into_iter()).unwrap();

        let symbol_commits = symbol_commits(&conn, &changes[0].symbol).unwrap();
        let all_commits = all_commits(&conn).unwrap();

        assert_eq!(
            symbol_commits,
            vec![changes[0].commit.clone(), changes[1].commit.clone()]
        );

        assert_eq!(
            all_commits,
            vec![
                changes[0].commit.clone(),
                changes[1].commit.clone(),
                changes[3].commit.clone()
            ]
        );
    }
}
