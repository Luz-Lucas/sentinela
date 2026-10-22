//! `sentinela full`: scan whole drives, quarantine hash-confirmed malware,
//! then clean. The orchestration lives here (and not in `cli`) so tests can
//! drive it with temp-dir roots, DB, quarantine and `Env`.
//!
//! Safety rule: only a finding from the `hash` detector ever causes a file to
//! be moved. YARA and PE findings are report-only.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;

use crate::clean::category::{Category, Env};
use crate::clean::{self, CleanReport};
use crate::quarantine::{self, QuarantineEntry};
use crate::scan::{Engine, Progress, ScanItem, ScanOptions, ScanReport, run_scan_with_progress};
use crate::signatures;
use crate::walker::{WalkError, WalkOptions};

pub struct FullOptions<'a> {
    /// Categories to clean. Production passes `clean::all_categories()`;
    /// tests pass tempdir-only ones (RecycleBin/WindowsUpdate ignore `Env`).
    pub categories: Vec<Box<dyn Category>>,
    pub roots: Vec<PathBuf>,
    pub db_dir: PathBuf,
    pub quarantine_dir: PathBuf,
    pub env: Env,
    pub elevated: bool,
    pub max_size: u64,
    pub cancel: &'a AtomicBool,
    /// Drives the scan phase only; the clean phase prints its own lines.
    pub progress: &'a dyn Progress,
}

#[derive(Debug, Serialize)]
pub struct QuarantineFailure {
    pub path: PathBuf,
    pub rule: String,
    pub reason: String,
}

#[derive(Serialize)]
pub struct FullReport {
    pub scanned: usize,
    pub interrupted: bool,
    pub scan_errors: Vec<WalkError>,
    /// Hash-confirmed malware moved to the quarantine.
    pub quarantined: Vec<QuarantineEntry>,
    /// Hash-confirmed malware that could not be moved (still on disk).
    pub quarantine_failures: Vec<QuarantineFailure>,
    /// YARA/PE detections: reported only, never touched.
    pub reported: Vec<ScanItem>,
    /// `None` when the run was interrupted before cleaning.
    pub clean: Option<CleanReport>,
    #[serde(skip)]
    pub warnings: Vec<String>,
    #[serde(skip)]
    pub db_initialized: bool,
}

impl FullReport {
    /// 1 if confirmed malware is still on disk (quarantine failed), else 0.
    pub fn exit_code(&self) -> i32 {
        i32::from(!self.quarantine_failures.is_empty())
    }
}

/// Quarantines the items that carry a `hash`-detector finding; everything
/// else is returned untouched as "reported". Items under `quarantine_dir`
/// (already quarantined bytes) are dropped.
pub fn quarantine_hash_hits(
    items: Vec<ScanItem>,
    quarantine_dir: &Path,
) -> (Vec<QuarantineEntry>, Vec<QuarantineFailure>, Vec<ScanItem>) {
    let mut done = Vec::new();
    let mut failed = Vec::new();
    let mut reported = Vec::new();
    for item in items {
        if is_inside(&item.path, quarantine_dir) {
            continue;
        }
        // The one and only trigger for moving a file.
        let Some(hit) = item.findings.iter().find(|f| f.detector == "hash") else {
            reported.push(item);
            continue;
        };
        let outcome = parse_sha256_rule(&hit.rule)
            .ok_or_else(|| format!("regra de hash inesperada: {}", hit.rule))
            .and_then(|sha| {
                quarantine::quarantine_file(quarantine_dir, &item.path, sha, &hit.rule)
                    .map_err(|e| format!("{e:#}"))
            });
        match outcome {
            Ok(entry) => done.push(entry),
            Err(reason) => failed.push(QuarantineFailure {
                path: item.path.clone(),
                rule: hit.rule.clone(),
                reason,
            }),
        }
    }
    (done, failed, reported)
}

/// `sha256:<64 hex>` as produced by the hash detector.
fn parse_sha256_rule(rule: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(rule.strip_prefix("sha256:")?, &mut out).ok()?;
    Some(out)
}

// Compares lossy-lowercased path strings on Windows: good enough for
// "is this under the quarantine dir" (worst case a file is reported, not moved).
fn is_inside(path: &Path, dir: &Path) -> bool {
    if cfg!(windows) {
        // Windows paths are case-insensitive.
        let lower = |p: &Path| PathBuf::from(p.to_string_lossy().to_lowercase());
        lower(path).starts_with(lower(dir))
    } else {
        path.starts_with(dir)
    }
}

pub fn run_full(opts: &FullOptions) -> FullReport {
    let db = signatures::load(&opts.db_dir);
    let (engine, engine_warnings) = Engine::from_database(&db);
    let mut warnings = db.warnings.clone();
    warnings.extend(engine_warnings);

    let scan = run_scan_with_progress(
        &engine,
        &ScanOptions {
            roots: opts.roots.clone(),
            walk: WalkOptions::default(),
            max_size: opts.max_size,
        },
        opts.cancel,
        opts.progress,
    );
    let ScanReport {
        scanned,
        items,
        errors,
        interrupted,
    } = scan;
    // Ctrl-C after the last file was scanned still means "stop".
    let interrupted = interrupted || opts.cancel.load(Ordering::Relaxed);
    let (quarantined, quarantine_failures, reported) =
        quarantine_hash_hits(items, &opts.quarantine_dir);

    // A stopped run must not go on to delete files.
    let clean = (!interrupted).then(|| {
        clean::run_clean(
            &opts.env,
            &opts.categories,
            &[],
            true,
            opts.elevated,
            &mut |_| true,
        )
    });
    FullReport {
        scanned,
        interrupted,
        scan_errors: errors,
        quarantined,
        quarantine_failures,
        reported,
        clean,
        warnings,
        db_initialized: db.manifest.is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clean::categories::UserTemp;
    use crate::scan::detector::{Finding, Severity};
    use crate::scan::hash::sha256_bytes;
    use sha2::{Digest, Sha256};
    use std::fs::{self, File};
    use std::time::{Duration, SystemTime};

    const HASH_MARKER: &str = "SENTINELA-FULL-HASH-MARKER-71c2";
    const YARA_MARKER: &str = "SENTINELA-FULL-YARA-MARKER-9b4e";

    fn finding(detector: &'static str, rule: &str, severity: Severity) -> Finding {
        Finding {
            detector,
            rule: rule.to_string(),
            severity,
            detail: "d".to_string(),
        }
    }

    fn hash_finding(bytes: &[u8]) -> Finding {
        finding(
            "hash",
            &format!("sha256:{}", hex::encode(sha256_bytes(bytes))),
            Severity::Malicious,
        )
    }

    fn item(path: &Path, findings: Vec<Finding>) -> ScanItem {
        let verdict = findings.iter().map(|f| f.severity).max().unwrap();
        ScanItem {
            path: path.to_path_buf(),
            verdict,
            findings,
        }
    }

    #[test]
    fn only_hash_findings_are_quarantined() {
        let tmp = tempfile::tempdir().unwrap();
        let q = tmp.path().join("q");
        let hash_hit = tmp.path().join("hash.bin");
        let yara_mal = tmp.path().join("yara.bin");
        let pe_susp = tmp.path().join("pe.bin");
        let both = tmp.path().join("both.bin");
        fs::write(&hash_hit, b"h").unwrap();
        fs::write(&yara_mal, b"y").unwrap();
        fs::write(&pe_susp, b"p").unwrap();
        fs::write(&both, b"b").unwrap();
        let items = vec![
            item(&hash_hit, vec![hash_finding(b"h")]),
            item(
                &yara_mal,
                vec![finding("yara", "Evil", Severity::Malicious)],
            ),
            item(
                &pe_susp,
                vec![finding("pe", "packed", Severity::Suspicious)],
            ),
            item(
                &both,
                vec![
                    finding("yara", "Evil", Severity::Malicious),
                    hash_finding(b"b"),
                ],
            ),
        ];
        let (done, failed, reported) = quarantine_hash_hits(items, &q);
        assert!(failed.is_empty(), "{failed:?}");
        let mut moved: Vec<_> = done.iter().map(|e| e.original_path.clone()).collect();
        moved.sort();
        assert_eq!(moved, vec![both.clone(), hash_hit.clone()]);
        assert!(!hash_hit.exists() && !both.exists());
        assert!(yara_mal.exists() && pe_susp.exists());
        let mut rep: Vec<_> = reported.iter().map(|i| i.path.clone()).collect();
        rep.sort();
        assert_eq!(rep, vec![pe_susp, yara_mal]);
        assert!(done[0].rule.starts_with("sha256:"));
    }

    #[test]
    fn changed_file_is_not_quarantined_and_is_reported_as_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("a.bin");
        fs::write(&p, b"different now").unwrap();
        let (done, failed, reported) = quarantine_hash_hits(
            vec![item(&p, vec![hash_finding(b"original")])],
            &tmp.path().join("q"),
        );
        assert!(done.is_empty() && reported.is_empty());
        assert_eq!(failed.len(), 1);
        assert_eq!(fs::read(&p).unwrap(), b"different now");
    }

    #[test]
    fn items_inside_quarantine_dir_are_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let q = tmp.path().join("q");
        let stored = q.join("files").join("abc");
        fs::create_dir_all(stored.parent().unwrap()).unwrap();
        fs::write(&stored, b"h").unwrap();
        let (done, failed, reported) =
            quarantine_hash_hits(vec![item(&stored, vec![hash_finding(b"h")])], &q);
        assert!(done.is_empty() && failed.is_empty() && reported.is_empty());
        assert!(stored.exists());
    }

    struct World {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        db: PathBuf,
        q: PathBuf,
        env: Env,
    }

    fn world() -> World {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let root = base.join("drive");
        fs::create_dir_all(&root).unwrap();
        let db = base.join("db");
        fs::create_dir_all(db.join("rules")).unwrap();
        fs::write(
            db.join("hashes.txt"),
            format!("{}\n", hex::encode(Sha256::digest(HASH_MARKER.as_bytes()))),
        )
        .unwrap();
        fs::write(
            db.join("rules/y.yar"),
            format!(
                "rule YaraOnly {{ meta: severity = \"malicious\" strings: $a = \"{YARA_MARKER}\" condition: $a }}"
            ),
        )
        .unwrap();
        let profile = base.join("profile");
        let temp = base.join("temp");
        let sysroot = base.join("windows");
        for d in [&profile, &temp, &sysroot.join("Temp")] {
            fs::create_dir_all(d).unwrap();
        }
        let env = Env {
            temp: Some(temp),
            local_app_data: Some(profile.join("AppData")),
            app_data: None,
            program_data: Some(base.join("pdata")),
            system_root: Some(sysroot),
            user_profile: Some(profile),
            now: SystemTime::now(),
            elevated: false,
            use_creation_time: false,
        };
        World {
            root,
            db,
            q: base.join("q"),
            env,
            _tmp: tmp,
        }
    }

    fn opts<'a>(w: &World, cancel: &'a AtomicBool) -> FullOptions<'a> {
        FullOptions {
            categories: vec![Box::new(UserTemp)],
            roots: vec![w.root.clone()],
            db_dir: w.db.clone(),
            quarantine_dir: w.q.clone(),
            env: w.env.clone(),
            elevated: false,
            max_size: 256 * 1024 * 1024,
            cancel,
            progress: &crate::scan::NoProgress,
        }
    }

    fn old_temp_file(w: &World) -> PathBuf {
        let p = w.env.temp.clone().unwrap().join("stale.tmp");
        fs::write(&p, b"junk").unwrap();
        let f = File::options().write(true).open(&p).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(3 * 24 * 3600))
            .unwrap();
        p
    }

    #[test]
    fn full_quarantines_hash_hit_reports_yara_and_cleans() {
        let w = world();
        let bad = w.root.join("bad.bin");
        let yara_only = w.root.join("yara.bin");
        let fine = w.root.join("fine.txt");
        fs::write(&bad, HASH_MARKER).unwrap();
        fs::write(&yara_only, YARA_MARKER).unwrap();
        fs::write(&fine, "hello").unwrap();
        let stale = old_temp_file(&w);

        let cancel = AtomicBool::new(false);
        let r = run_full(&opts(&w, &cancel));

        assert!(!bad.exists(), "hash-confirmed file must be quarantined");
        assert_eq!(r.quarantined.len(), 1);
        assert_eq!(r.quarantined[0].original_path, bad);
        assert!(yara_only.exists(), "yara-only match must stay on disk");
        assert!(fine.exists());
        assert_eq!(r.reported.len(), 1);
        assert_eq!(r.reported[0].path, yara_only);
        assert!(r.quarantine_failures.is_empty());
        assert_eq!(r.exit_code(), 0);
        assert!(!r.db_initialized, "test DB has no manifest");
        assert!(!stale.exists(), "old temp file must be cleaned");
        assert!(r.clean.is_some());
        assert_eq!(crate::quarantine::list(&w.q).len(), 1);
        // Reversible.
        crate::quarantine::restore(&w.q, &r.quarantined[0].id).unwrap();
        assert_eq!(fs::read(&bad).unwrap(), HASH_MARKER.as_bytes());
    }

    #[test]
    fn rerun_does_not_requarantine_quarantined_bytes_inside_scan_root() {
        let mut w = world();
        // Quarantine lives inside the scanned root, like C:\Users\..\AppData on C:.
        w.q = w.root.join("quarantine");
        fs::write(w.root.join("bad.bin"), HASH_MARKER).unwrap();
        let cancel = AtomicBool::new(false);
        let first = run_full(&opts(&w, &cancel));
        assert_eq!(first.quarantined.len(), 1);
        let second = run_full(&opts(&w, &cancel));
        assert!(second.quarantined.is_empty());
        assert!(second.quarantine_failures.is_empty());
        assert!(second.reported.is_empty());
        assert_eq!(crate::quarantine::list(&w.q).len(), 1);
        assert!(w.q.join("files").join(&first.quarantined[0].id).exists());
    }

    #[test]
    fn interrupted_scan_skips_cleaning() {
        let w = world();
        let stale = old_temp_file(&w);
        let cancel = AtomicBool::new(true);
        let r = run_full(&opts(&w, &cancel));
        assert!(r.interrupted);
        assert!(r.clean.is_none());
        assert!(stale.exists());
    }
}
