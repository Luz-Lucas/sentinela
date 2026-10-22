//! Large and duplicate file finder. Read-only: never deletes, moves or writes.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::scan::hash::sha256_file;
use crate::walker::{WalkError, WalkItem, WalkOptions, walk};

const PREFIX_LEN: u64 = 64 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct LargeFile {
    pub path: PathBuf,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DupGroup {
    pub size: u64,
    pub sha256: String,
    pub paths: Vec<PathBuf>,
}

pub fn find_large(
    roots: &[PathBuf],
    top: usize,
    min_size: u64,
) -> (Vec<LargeFile>, Vec<WalkError>) {
    let mut files = Vec::new();
    let mut errors = Vec::new();
    for item in walk(roots, &WalkOptions::default()) {
        match item {
            WalkItem::File(e) if e.size >= min_size => files.push(LargeFile {
                path: e.path,
                size: e.size,
            }),
            WalkItem::File(_) => {}
            WalkItem::Error(err) => errors.push(err),
        }
    }
    files.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.path.cmp(&b.path)));
    files.truncate(top);
    (files, errors)
}

pub fn find_dupes(roots: &[PathBuf], min_size: u64) -> (Vec<DupGroup>, Vec<WalkError>) {
    let mut errors = Vec::new();
    let mut by_size: HashMap<u64, Vec<PathBuf>> = HashMap::new();
    for item in walk(roots, &WalkOptions::default()) {
        match item {
            WalkItem::File(e) if e.size > 0 && e.size >= min_size => {
                by_size.entry(e.size).or_default().push(e.path)
            }
            WalkItem::File(_) => {}
            WalkItem::Error(err) => errors.push(err),
        }
    }

    let mut groups = Vec::new();
    for (size, paths) in by_size.into_iter().filter(|(_, p)| p.len() > 1) {
        let mut by_prefix: HashMap<[u8; 32], Vec<PathBuf>> = HashMap::new();
        for path in paths {
            match prefix_hash(&path) {
                Ok(h) => by_prefix.entry(h).or_default().push(path),
                Err(e) => errors.push(WalkError {
                    path,
                    reason: e.to_string(),
                }),
            }
        }
        for paths in by_prefix.into_values().filter(|p| p.len() > 1) {
            let mut by_full: HashMap<[u8; 32], Vec<PathBuf>> = HashMap::new();
            for path in paths {
                match sha256_file(&path) {
                    Ok(h) => by_full.entry(h).or_default().push(path),
                    Err(e) => errors.push(WalkError {
                        path,
                        reason: e.to_string(),
                    }),
                }
            }
            for (hash, mut paths) in by_full.into_iter().filter(|(_, p)| p.len() > 1) {
                paths.sort();
                groups.push(DupGroup {
                    size,
                    sha256: hex::encode(hash),
                    paths,
                });
            }
        }
    }
    groups.sort_by(|a, b| {
        let wa = a.size * (a.paths.len() as u64 - 1);
        let wb = b.size * (b.paths.len() as u64 - 1);
        wb.cmp(&wa).then_with(|| a.paths.cmp(&b.paths))
    });
    (groups, errors)
}

fn prefix_hash(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut buf = Vec::with_capacity(PREFIX_LEN as usize);
    File::open(path)?.take(PREFIX_LEN).read_to_end(&mut buf)?;
    Ok(Sha256::digest(&buf).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, data).unwrap();
        p
    }

    #[test]
    fn top_n_largest() {
        let d = tempdir().unwrap();
        for (i, n) in [10usize, 50, 30, 20, 40].iter().enumerate() {
            write(d.path(), &format!("f{i}"), &vec![1u8; *n]);
        }
        let (r, errs) = find_large(&[d.path().to_path_buf()], 2, 0);
        assert!(errs.is_empty());
        let sizes: Vec<u64> = r.iter().map(|f| f.size).collect();
        assert_eq!(sizes, vec![50, 40]);
    }

    #[test]
    fn min_size_filters() {
        let d = tempdir().unwrap();
        write(d.path(), "a", &[0u8; 10]);
        write(d.path(), "b", &[0u8; 100]);
        let (r, _) = find_large(&[d.path().to_path_buf()], 10, 50);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].size, 100);
    }

    #[test]
    fn finds_duplicates() {
        let d = tempdir().unwrap();
        for n in ["a", "b", "c"] {
            write(d.path(), n, b"same content");
        }
        write(d.path(), "d", b"diff content");
        let (g, errs) = find_dupes(&[d.path().to_path_buf()], 0);
        assert!(errs.is_empty());
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].paths.len(), 3);
        assert_eq!(g[0].size, 12);
        assert_eq!(g[0].sha256.len(), 64);
    }

    #[test]
    fn same_prefix_different_tail_not_dupes() {
        let d = tempdir().unwrap();
        let mut a = vec![7u8; 100 * 1024];
        let mut b = a.clone();
        a[100 * 1024 - 1] = 1;
        b[100 * 1024 - 1] = 2;
        write(d.path(), "a", &a);
        write(d.path(), "b", &b);
        let (g, _) = find_dupes(&[d.path().to_path_buf()], 0);
        assert!(g.is_empty());
    }

    #[test]
    fn empty_files_never_dupes() {
        let d = tempdir().unwrap();
        write(d.path(), "a", b"");
        write(d.path(), "b", b"");
        let (g, _) = find_dupes(&[d.path().to_path_buf()], 0);
        assert!(g.is_empty());
    }

    #[test]
    fn groups_sorted_by_wasted_space() {
        let d = tempdir().unwrap();
        write(d.path(), "s1", b"aa");
        write(d.path(), "s2", b"aa");
        write(d.path(), "b1", &[9u8; 1000]);
        write(d.path(), "b2", &[9u8; 1000]);
        let (g, _) = find_dupes(&[d.path().to_path_buf()], 0);
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].size, 1000);
    }

    #[test]
    fn never_deletes() {
        let d = tempdir().unwrap();
        let ps: Vec<PathBuf> = ["a", "b", "c"]
            .iter()
            .map(|n| write(d.path(), n, b"xyz"))
            .collect();
        let _ = find_large(&[d.path().to_path_buf()], 5, 0);
        let _ = find_dupes(&[d.path().to_path_buf()], 0);
        assert!(ps.iter().all(|p| p.exists()));
    }
}
