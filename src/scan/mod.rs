pub mod detector;
pub mod hash;
pub mod pe;
pub mod yara;

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use rayon::prelude::*;
use serde::Serialize;

use crate::signatures::Database;
use crate::walker::{Entry, WalkError, WalkItem, WalkOptions, walk};
use detector::{Detector, FileData, Finding, Severity};

pub struct ScanOptions {
    pub roots: Vec<PathBuf>,
    pub walk: WalkOptions,
    /// Files larger than this (bytes) are only hashed, streaming.
    pub max_size: u64,
}

#[derive(Debug, Serialize)]
pub struct ScanItem {
    pub path: PathBuf,
    pub verdict: Severity,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub scanned: usize,
    pub items: Vec<ScanItem>,
    pub errors: Vec<WalkError>,
    pub interrupted: bool,
}

impl ScanReport {
    /// 1 if any file is Suspicious or worse, otherwise 0.
    pub fn exit_code(&self) -> i32 {
        i32::from(self.items.iter().any(|i| i.verdict >= Severity::Suspicious))
    }
}

pub struct Engine {
    hash: hash::HashDetector,
    /// Detectors that need the file contents (YARA, PE).
    content: Vec<Box<dyn Detector>>,
    /// Serializes full reads of files above `BIG_FILE`.
    big_read: Mutex<()>,
}

/// Files above this size are read one at a time.
const BIG_FILE: u64 = 32 * 1024 * 1024;

impl Engine {
    pub fn from_database(db: &Database) -> (Engine, Vec<String>) {
        let mut warnings = Vec::new();
        let mut content: Vec<Box<dyn Detector>> = Vec::new();
        let outcome = yara::compile_rules(&db.rule_sources);
        for (name, err) in outcome.rejected {
            warnings.push(format!("regra rejeitada {name}: {err}"));
        }
        if let Some(rules) = outcome.rules {
            content.push(Box::new(yara::YaraDetector::new(rules)));
        }
        content.push(Box::new(pe::PeDetector));
        let engine = Engine {
            hash: hash::HashDetector::new(db.hashes.clone()),
            content,
            big_read: Mutex::new(()),
        };
        (engine, warnings)
    }
}

fn walk_error(path: &Path, e: impl std::fmt::Display) -> WalkError {
    WalkError {
        path: path.to_path_buf(),
        reason: e.to_string(),
    }
}

/// Scans one file. Returns the verdict and findings, or a `WalkError` if the
/// file could not be read.
fn scan_entry(
    engine: &Engine,
    entry: &Entry,
    max_size: u64,
) -> Result<(Severity, Vec<Finding>), WalkError> {
    let path = entry.path.as_path();
    // Big full reads are serialized to bound peak memory.
    let _guard = (entry.size > BIG_FILE && entry.size <= max_size)
        .then(|| engine.big_read.lock().unwrap_or_else(|p| p.into_inner()));
    let full = if entry.size <= max_size {
        let mut bytes = Vec::new();
        File::open(path)
            .and_then(|f| f.take(max_size.saturating_add(1)).read_to_end(&mut bytes))
            .map_err(|e| walk_error(path, e))?;
        // Grew past the limit after the walk: fall back to hash-only.
        (bytes.len() as u64 <= max_size).then_some(bytes)
    } else {
        None
    };
    let mut findings = if let Some(bytes) = full {
        let data = FileData {
            path,
            sha256: hash::sha256_bytes(&bytes),
            bytes: Some(&bytes),
        };
        let mut f = engine.hash.inspect(&data);
        for d in &engine.content {
            f.extend(d.inspect(&data));
        }
        f
    } else {
        let data = FileData {
            path,
            bytes: None,
            sha256: hash::sha256_file(path).map_err(|e| walk_error(path, e))?,
        };
        engine.hash.inspect(&data)
    };
    findings.sort_by_key(|a| std::cmp::Reverse(a.severity));
    let verdict = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info);
    Ok((verdict, findings))
}

pub fn run_scan(engine: &Engine, opts: &ScanOptions, cancel: &AtomicBool) -> ScanReport {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    let mut skipped_in_walk = false;
    for item in walk(&opts.roots, &opts.walk) {
        if cancel.load(Ordering::Relaxed) {
            skipped_in_walk = true;
            break;
        }
        match item {
            WalkItem::File(e) => entries.push(e),
            WalkItem::Error(e) => errors.push(e),
        }
    }

    let skipped = AtomicBool::new(skipped_in_walk);
    let results: Vec<Result<Option<ScanItem>, WalkError>> = entries
        .par_iter()
        .filter_map(|entry| {
            if cancel.load(Ordering::Relaxed) {
                skipped.store(true, Ordering::Relaxed);
                return None;
            }
            Some(
                scan_entry(engine, entry, opts.max_size).map(|(verdict, findings)| {
                    (verdict >= Severity::Suspicious).then(|| ScanItem {
                        path: entry.path.clone(),
                        verdict,
                        findings,
                    })
                }),
            )
        })
        .collect();

    let mut scanned = 0;
    let mut items = Vec::new();
    for r in results {
        match r {
            Ok(item) => {
                scanned += 1;
                items.extend(item);
            }
            Err(e) => errors.push(e),
        }
    }
    items.sort_by(|a, b| a.path.cmp(&b.path));
    errors.sort_by(|a, b| a.path.cmp(&b.path));
    ScanReport {
        scanned,
        items,
        errors,
        interrupted: skipped.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::Database;
    use std::collections::HashSet;
    use std::fs;
    use std::sync::atomic::AtomicBool;

    const MARKER: &[u8] = b"SENTINELA-HARMLESS-TEST-MARKER";
    const MARKER_RULE: &str = r#"rule Marker { meta: severity = "malicious" strings: $a = "SENTINELA-HARMLESS-TEST-MARKER" condition: $a }"#;

    fn marker_db() -> Database {
        let mut hashes = HashSet::new();
        hashes.insert(hash::sha256_bytes(MARKER));
        Database {
            hashes,
            rule_sources: vec![("marker".into(), MARKER_RULE.into())],
            manifest: None,
            warnings: vec![],
        }
    }

    fn opts(dir: &Path, max_size: u64) -> ScanOptions {
        ScanOptions {
            roots: vec![dir.to_path_buf()],
            walk: WalkOptions::default(),
            max_size,
        }
    }

    fn assert_malicious(report: &ScanReport) {
        assert_eq!(report.items.len(), 1);
        let item = &report.items[0];
        assert_eq!(item.verdict, Severity::Malicious);
        assert!(item.findings.iter().any(|f| f.detector == "hash"));
        assert!(item.findings.iter().any(|f| f.detector == "yara"));
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn detects_marker_file_all_platforms() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("m.bin"), MARKER).unwrap();
        let (engine, warnings) = Engine::from_database(&marker_db());
        assert!(warnings.is_empty());
        let report = run_scan(&engine, &opts(dir.path(), 1 << 20), &AtomicBool::new(false));
        assert_malicious(&report);
    }

    #[cfg(not(windows))]
    #[test]
    fn detects_eicar_file() {
        use crate::signatures::EICAR;
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("eicar.com"), EICAR).unwrap();
        let db = crate::signatures::load(dir.path().join("nodb").as_path());
        let (engine, _) = Engine::from_database(&db);
        let report = run_scan(&engine, &opts(dir.path(), 1 << 20), &AtomicBool::new(false));
        assert_malicious(&report);
    }

    #[test]
    fn clean_folder_exit_zero() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        fs::write(dir.path().join("b.txt"), b"world").unwrap();
        let (engine, _) = Engine::from_database(&marker_db());
        let report = run_scan(&engine, &opts(dir.path(), 1 << 20), &AtomicBool::new(false));
        assert!(report.items.is_empty());
        assert_eq!(report.scanned, 2);
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn large_file_only_hashed() {
        let dir = tempfile::tempdir().unwrap();
        let mut data = vec![b'a'; 100];
        data[10..15].copy_from_slice(b"XYZZY");
        fs::write(dir.path().join("big.bin"), &data).unwrap();
        let db = Database {
            hashes: HashSet::new(),
            rule_sources: vec![(
                "x".into(),
                r#"rule X { meta: severity = "malicious" strings: $a = "XYZZY" condition: $a }"#
                    .into(),
            )],
            manifest: None,
            warnings: vec![],
        };
        let (engine, _) = Engine::from_database(&db);
        let report = run_scan(&engine, &opts(dir.path(), 10), &AtomicBool::new(false));
        assert!(report.items.is_empty());
        assert_eq!(report.scanned, 1);
        // Same file under the limit is detected.
        let report = run_scan(&engine, &opts(dir.path(), 1000), &AtomicBool::new(false));
        assert_eq!(report.items.len(), 1);
    }

    #[test]
    fn large_file_hash_still_detected() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("m.bin"), MARKER).unwrap();
        let (engine, _) = Engine::from_database(&marker_db());
        let report = run_scan(&engine, &opts(dir.path(), 5), &AtomicBool::new(false));
        assert_eq!(report.items.len(), 1);
        assert!(
            report.items[0]
                .findings
                .iter()
                .all(|f| f.detector == "hash")
        );
    }

    #[test]
    fn unicode_path_reported() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("relatório_ção.txt"), MARKER).unwrap();
        let (engine, _) = Engine::from_database(&marker_db());
        let report = run_scan(&engine, &opts(dir.path(), 1 << 20), &AtomicBool::new(false));
        assert_eq!(report.items.len(), 1);
        assert!(report.items[0].path.ends_with("relatório_ção.txt"));
        let mut out = Vec::new();
        crate::report::write_scan(&report, true, &mut out).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let p = v["items"][0]["path"].as_str().unwrap();
        assert!(p.ends_with("relatório_ção.txt"));
    }

    #[test]
    fn vanished_file_is_error_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gone.txt");
        fs::write(&path, b"x").unwrap();
        let entry = Entry {
            path: path.clone(),
            size: 1,
            modified: std::time::SystemTime::now(),
        };
        fs::remove_file(&path).unwrap();
        let (engine, _) = Engine::from_database(&marker_db());
        let err = scan_entry(&engine, &entry, 1 << 20).unwrap_err();
        assert_eq!(err.path, path);
        assert!(!err.reason.is_empty());
    }

    #[test]
    fn cancel_sets_interrupted() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        let (engine, _) = Engine::from_database(&marker_db());
        let report = run_scan(&engine, &opts(dir.path(), 1 << 20), &AtomicBool::new(true));
        assert!(report.interrupted);
        assert_eq!(report.scanned, 0);
    }

    struct CancelOnInspect(std::sync::Arc<AtomicBool>);
    impl Detector for CancelOnInspect {
        fn name(&self) -> &'static str {
            "cancel"
        }
        fn inspect(&self, _file: &FileData) -> Vec<Finding> {
            self.0.store(true, Ordering::Relaxed);
            Vec::new()
        }
    }

    #[test]
    fn cancel_mid_scan_sets_interrupted() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..20 {
            fs::write(dir.path().join(format!("f{i}.txt")), b"hello").unwrap();
        }
        let flag = std::sync::Arc::new(AtomicBool::new(false));
        let (mut engine, _) = Engine::from_database(&marker_db());
        engine.content.push(Box::new(CancelOnInspect(flag.clone())));
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let report = pool.install(|| run_scan(&engine, &opts(dir.path(), 1 << 20), &flag));
        assert!(report.interrupted);
        assert!(report.scanned >= 1 && report.scanned < 20);
    }

    #[test]
    fn late_cancel_does_not_mark_interrupted() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        let flag = std::sync::Arc::new(AtomicBool::new(false));
        let (mut engine, _) = Engine::from_database(&marker_db());
        engine.content.push(Box::new(CancelOnInspect(flag.clone())));
        let report = run_scan(&engine, &opts(dir.path(), 1 << 20), &flag);
        assert_eq!(report.scanned, 1);
        assert!(!report.interrupted);
    }

    #[test]
    fn rejected_rule_gives_warning() {
        let mut db = marker_db();
        db.rule_sources.push(("bad".into(), "rule {".into()));
        let (_, warnings) = Engine::from_database(&db);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("bad"));
    }
}
