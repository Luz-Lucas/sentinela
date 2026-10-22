//! Safe directory traversal: never follows symlinks or junctions.

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
    pub created: Option<SystemTime>,
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
    /// Treat ANY reparse point (not only symlinks/junctions) as a link. Used
    /// by the cleaner, which must never touch cloud placeholders or the like.
    pub strict_links: bool,
}

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_ATTRIBUTE_OFFLINE: u32 = 0x1000;
const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryClass {
    Normal,
    /// Symlink / junction (or, in strict mode, any reparse point).
    Link,
    /// Cloud-only placeholder: reading it would trigger a download.
    CloudOnly,
}

/// Pure classification from Windows file attributes and the std symlink flag
/// (`FileType::is_symlink`, which on Windows covers symlinks and junctions).
pub fn classify_attrs(attrs: u32, is_symlink: bool, strict: bool) -> EntryClass {
    if is_symlink || (strict && attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0) {
        EntryClass::Link
    } else if attrs & (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_OFFLINE) != 0 {
        EntryClass::CloudOnly
    } else {
        EntryClass::Normal
    }
}

/// Creation time when the platform reports it. Unit tests report `None`
/// because creation time cannot be backdated on Linux; the age rule itself is
/// covered by the pure `effective_age` tests.
pub(crate) fn created_of(meta: &Metadata) -> Option<SystemTime> {
    #[cfg(test)]
    {
        let _ = meta;
        None
    }
    #[cfg(not(test))]
    {
        meta.created().ok()
    }
}

fn attrs_of(meta: &Metadata) -> u32 {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes()
    }
    #[cfg(not(windows))]
    {
        let _ = meta;
        0
    }
}

fn classify(meta: &Metadata, strict: bool) -> EntryClass {
    classify_attrs(attrs_of(meta), meta.file_type().is_symlink(), strict)
}

/// Strict: true for symlinks and, on Windows, ANY reparse point. Used by the
/// cleaner's deletion checks and browser profile discovery.
pub fn is_link_like(meta: &Metadata) -> bool {
    classify(meta, true) == EntryClass::Link
}

/// Walker traversal: symlinks and junctions (name-surrogate reparse points).
/// Other reparse points (e.g. OneDrive) are walked normally.
pub fn is_traversal_link(meta: &Metadata) -> bool {
    classify(meta, false) == EntryClass::Link
}

pub fn walk<'a>(
    roots: &'a [PathBuf],
    opts: &'a WalkOptions,
) -> impl Iterator<Item = WalkItem> + 'a {
    roots.iter().flat_map(move |root| {
        let mut it = WalkDir::new(root)
            .follow_links(false)
            .follow_root_links(false)
            .into_iter()
            .filter_entry(move |e| {
                if e.depth() == 0 {
                    return true;
                }
                match &opts.excludes {
                    Some(set) => !set.is_match(e.path()),
                    None => true,
                }
            });
        std::iter::from_fn(move || {
            loop {
                let entry = match it.next()? {
                    Err(err) => {
                        return Some(WalkItem::Error(WalkError {
                            path: err.path().map(PathBuf::from).unwrap_or_default(),
                            reason: err.to_string(),
                        }));
                    }
                    Ok(entry) => entry,
                };
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(err) => {
                        return Some(WalkItem::Error(WalkError {
                            path: entry.path().to_path_buf(),
                            reason: err.to_string(),
                        }));
                    }
                };
                let class = classify(&meta, opts.strict_links);
                if class == EntryClass::Link {
                    if meta.is_dir() {
                        // Strict mode: never descend into a reparse-point
                        // directory that is not itself a symlink/junction (e.g. a
                        // OneDrive placeholder folder). Real symlinks never reach
                        // here as a directory (lstat reports them as links).
                        it.skip_current_dir();
                        return Some(WalkItem::Error(WalkError {
                            path: entry.path().to_path_buf(),
                            reason: "ponto de reparse ignorado".to_string(),
                        }));
                    }
                    return Some(WalkItem::Error(WalkError {
                        path: entry.path().to_path_buf(),
                        reason: "link simbólico/junção ignorado".to_string(),
                    }));
                }
                if !meta.is_file() {
                    continue;
                }
                if class == EntryClass::CloudOnly {
                    return Some(WalkItem::Error(WalkError {
                        path: entry.path().to_path_buf(),
                        reason: "arquivo somente na nuvem (não baixado); não verificado"
                            .to_string(),
                    }));
                }
                match meta.modified() {
                    Ok(modified) => {
                        return Some(WalkItem::File(Entry {
                            path: entry.into_path(),
                            size: meta.len(),
                            modified,
                            created: created_of(&meta),
                        }));
                    }
                    Err(err) => {
                        return Some(WalkItem::Error(WalkError {
                            path: entry.path().to_path_buf(),
                            reason: err.to_string(),
                        }));
                    }
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
            ..WalkOptions::default()
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
    fn symlinked_dir_is_reported_as_error() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), b"s").unwrap();
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
        let roots = vec![root.path().to_path_buf()];
        let items: Vec<_> = walk(&roots, &WalkOptions::default()).collect();
        assert_eq!(items.len(), 1);
        match &items[0] {
            WalkItem::Error(e) => assert!(e.reason.contains("link simbólico"), "{}", e.reason),
            _ => panic!("expected error"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_root_yields_error() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), b"s").unwrap();
        let holder = tempfile::tempdir().unwrap();
        let link = holder.path().join("rootlink");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        let roots = vec![link];
        let items: Vec<_> = walk(&roots, &WalkOptions::default()).collect();
        assert_eq!(items.len(), 1);
        assert!(matches!(items[0], WalkItem::Error(_)));
    }

    #[test]
    fn strict_mode_still_descends_into_normal_dirs() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir_all(d.path().join("a/b")).unwrap();
        fs::write(d.path().join("a/b/deep.txt"), b"x").unwrap();
        let roots = vec![d.path().to_path_buf()];
        let opts = WalkOptions {
            strict_links: true,
            ..WalkOptions::default()
        };
        let v = files_of(walk(&roots, &opts).collect());
        assert_eq!(v.len(), 1);
        assert!(v[0].path.ends_with("a/b/deep.txt"));
    }

    #[test]
    fn classify_attrs_rules() {
        const REPARSE: u32 = 0x400;
        const RECALL: u32 = 0x0040_0000;
        const OFFLINE: u32 = 0x1000;
        assert_eq!(classify_attrs(0x20, false, false), EntryClass::Normal);
        assert_eq!(classify_attrs(0, true, false), EntryClass::Link);
        // OneDrive placeholder: reparse point + recall flag.
        assert_eq!(
            classify_attrs(REPARSE | RECALL, false, false),
            EntryClass::CloudOnly
        );
        assert_eq!(classify_attrs(OFFLINE, false, false), EntryClass::CloudOnly);
        // Other reparse points are walked normally unless strict.
        assert_eq!(classify_attrs(REPARSE, false, false), EntryClass::Normal);
        assert_eq!(classify_attrs(REPARSE, false, true), EntryClass::Link);
        assert_eq!(
            classify_attrs(REPARSE | RECALL, false, true),
            EntryClass::Link
        );
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
