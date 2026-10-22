//! Safe directory traversal: never follows symlinks, junctions or reparse points.

use std::fs::Metadata;
use std::path::PathBuf;
use std::time::SystemTime;

use serde::Serialize;
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct Entry {
    pub path: PathBuf,
    pub size: u64,
    pub modified: SystemTime,
}

#[derive(Debug, Clone, Serialize)]
pub struct WalkError {
    pub path: PathBuf,
    pub reason: String,
}

pub enum WalkItem {
    File(Entry),
    Error(WalkError),
}

#[derive(Default)]
pub struct WalkOptions {
    pub excludes: Option<globset::GlobSet>,
}

/// True for symlinks and, on Windows, any reparse point (junctions etc.).
pub fn is_link_like(meta: &Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

pub fn walk<'a>(
    roots: &'a [PathBuf],
    opts: &'a WalkOptions,
) -> impl Iterator<Item = WalkItem> + 'a {
    roots.iter().flat_map(move |root| {
        WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(move |e| {
                if e.depth() == 0 {
                    return true;
                }
                // Prune link-like directories (junctions, reparse points) so
                // we never descend into them.
                if e.metadata().is_ok_and(|m| is_link_like(&m)) {
                    return false;
                }
                match &opts.excludes {
                    Some(set) => !set.is_match(e.path()),
                    None => true,
                }
            })
            .filter_map(|res| match res {
                Err(err) => Some(WalkItem::Error(WalkError {
                    path: err.path().map(PathBuf::from).unwrap_or_default(),
                    reason: err.to_string(),
                })),
                Ok(entry) => {
                    let meta = match entry.metadata() {
                        Ok(m) => m,
                        Err(err) => {
                            return Some(WalkItem::Error(WalkError {
                                path: entry.path().to_path_buf(),
                                reason: err.to_string(),
                            }));
                        }
                    };
                    if is_link_like(&meta) || !meta.is_file() {
                        return None;
                    }
                    match meta.modified() {
                        Ok(modified) => Some(WalkItem::File(Entry {
                            path: entry.into_path(),
                            size: meta.len(),
                            modified,
                        })),
                        Err(err) => Some(WalkItem::Error(WalkError {
                            path: entry.path().to_path_buf(),
                            reason: err.to_string(),
                        })),
                    }
                }
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn files_of(items: Vec<WalkItem>) -> Vec<Entry> {
        items
            .into_iter()
            .filter_map(|i| match i {
                WalkItem::File(e) => Some(e),
                WalkItem::Error(_) => None,
            })
            .collect()
    }

    #[test]
    fn walks_nested_files() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir_all(d.path().join("a/b")).unwrap();
        fs::write(d.path().join("one.txt"), b"1").unwrap();
        fs::write(d.path().join("a/two.txt"), b"22").unwrap();
        fs::write(d.path().join("a/b/three.txt"), b"333").unwrap();
        let roots = vec![d.path().to_path_buf()];
        let opts = WalkOptions::default();
        let mut v = files_of(walk(&roots, &opts).collect());
        v.sort_by_key(|e| e.size);
        assert_eq!(v.iter().map(|e| e.size).collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    #[test]
    fn file_root_yields_single_entry() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("x.bin");
        fs::write(&f, b"abcd").unwrap();
        let roots = vec![f.clone()];
        let opts = WalkOptions::default();
        let v = files_of(walk(&roots, &opts).collect());
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].path, f);
        assert_eq!(v[0].size, 4);
    }

    #[test]
    fn missing_root_yields_error() {
        let d = tempfile::tempdir().unwrap();
        let roots = vec![d.path().join("nope")];
        let opts = WalkOptions::default();
        let items: Vec<_> = walk(&roots, &opts).collect();
        assert_eq!(items.len(), 1);
        assert!(matches!(items[0], WalkItem::Error(_)));
    }

    #[test]
    fn excludes_glob() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("a.log"), b"x").unwrap();
        fs::write(d.path().join("a.txt"), b"x").unwrap();
        let mut b = globset::GlobSetBuilder::new();
        b.add(globset::Glob::new("**/*.log").unwrap());
        let opts = WalkOptions {
            excludes: Some(b.build().unwrap()),
        };
        let roots = vec![d.path().to_path_buf()];
        let v = files_of(walk(&roots, &opts).collect());
        assert_eq!(v.len(), 1);
        assert!(v[0].path.ends_with("a.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn does_not_follow_symlinked_dir() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), b"s").unwrap();
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("in.txt"), b"i").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
        let roots = vec![root.path().to_path_buf()];
        let opts = WalkOptions::default();
        let v = files_of(walk(&roots, &opts).collect());
        assert_eq!(v.len(), 1);
        assert!(v[0].path.ends_with("in.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_loop_terminates() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("sub")).unwrap();
        fs::write(root.path().join("sub/f.txt"), b"f").unwrap();
        std::os::unix::fs::symlink("..", root.path().join("sub/loop")).unwrap();
        let roots = vec![root.path().to_path_buf()];
        let opts = WalkOptions::default();
        let v = files_of(walk(&roots, &opts).collect());
        assert_eq!(v.len(), 1);
    }
}
