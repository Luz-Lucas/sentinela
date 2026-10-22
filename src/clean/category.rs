//! Cleaning core: the `Category` trait, root safety checks and checked deletion.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;

use crate::walker::{Entry, WalkItem, WalkOptions, is_link_like, walk};

/// Environment the categories resolve their roots from.
#[derive(Debug, Clone)]
pub struct Env {
    pub temp: Option<PathBuf>,
    pub local_app_data: Option<PathBuf>,
    pub app_data: Option<PathBuf>,
    pub program_data: Option<PathBuf>,
    pub system_root: Option<PathBuf>,
    pub user_profile: Option<PathBuf>,
    pub now: SystemTime,
}

fn var_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

impl Env {
    pub fn from_system() -> Env {
        Env {
            temp: var_path("TEMP").or_else(|| var_path("TMP")),
            local_app_data: var_path("LOCALAPPDATA"),
            app_data: var_path("APPDATA"),
            program_data: var_path("ProgramData"),
            system_root: var_path("SystemRoot"),
            user_profile: var_path("USERPROFILE"),
            now: SystemTime::now(),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct Candidate {
    pub path: PathBuf,
    pub size: u64,
}

#[derive(Debug, Serialize, Default)]
pub struct Plan {
    pub items: Vec<Candidate>,
    pub files: u64,
    pub bytes: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize, Default)]
pub struct ApplyReport {
    pub deleted: u64,
    pub freed: u64,
    pub skipped: Vec<(PathBuf, String)>,
}

pub trait Category: Send + Sync {
    fn id(&self) -> &'static str;
    fn needs_admin(&self) -> bool;
    fn roots(&self, env: &Env) -> Vec<PathBuf>;
    fn plan(&self, env: &Env) -> Plan;
    fn apply(&self, env: &Env, plan: &Plan) -> ApplyReport;
}

/// Canonical form when the path exists, otherwise the path as given.
fn normalize(p: &Path) -> PathBuf {
    fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// False for drive roots, "/", the user profile, the system root, and any
/// ancestor of the latter two.
pub fn safe_root(p: &Path, env: &Env) -> bool {
    if p.as_os_str().is_empty() || p.parent().is_none() {
        return false;
    }
    let norm = normalize(p);
    if norm.parent().is_none() {
        return false;
    }
    for protected in [&env.user_profile, &env.system_root].into_iter().flatten() {
        let prot_norm = normalize(protected);
        // Equal to or an ancestor of a protected directory (checked on both
        // the raw and the canonical forms).
        if protected.starts_with(p) || prot_norm.starts_with(&norm) {
            return false;
        }
    }
    true
}

/// Walks `roots` and collects every file for which `keep` is true.
pub fn plan_files(roots: &[PathBuf], keep: impl Fn(&Entry) -> bool) -> Plan {
    let mut plan = Plan::default();
    let opts = WalkOptions::default();
    for item in walk(roots, &opts) {
        match item {
            WalkItem::File(e) => {
                if keep(&e) {
                    plan.files += 1;
                    plan.bytes += e.size;
                    plan.items.push(Candidate {
                        path: e.path,
                        size: e.size,
                    });
                }
            }
            WalkItem::Error(err) => {
                plan.warnings
                    .push(format!("{}: {}", err.path.display(), err.reason))
            }
        }
    }
    plan
}

/// Deletes the plan's files, but only regular files that resolve inside one of
/// `roots`. Links are never followed or removed. Empty sub-directories are
/// pruned afterwards (bottom-up, never the roots themselves).
pub fn delete_checked(roots: &[PathBuf], plan: &Plan) -> ApplyReport {
    let mut report = ApplyReport::default();
    let canon_roots: Vec<PathBuf> = roots
        .iter()
        .filter_map(|r| fs::canonicalize(r).ok())
        .collect();

    for cand in &plan.items {
        let path = &cand.path;
        match delete_one(path, &canon_roots) {
            Ok(size) => {
                report.deleted += 1;
                report.freed += size;
            }
            Err(reason) => report.skipped.push((path.clone(), reason)),
        }
    }

    if report.deleted > 0 {
        for root in &canon_roots {
            prune_empty_dirs(root, true);
        }
    }
    report
}

fn delete_one(path: &Path, canon_roots: &[PathBuf]) -> Result<u64, String> {
    let meta =
        fs::symlink_metadata(path).map_err(|e| format!("não foi possível ler o arquivo: {e}"))?;
    if is_link_like(&meta) {
        return Err("link simbólico ou ponto de reanálise ignorado".into());
    }
    if !meta.is_file() {
        return Err("não é um arquivo comum".into());
    }
    let canon =
        fs::canonicalize(path).map_err(|e| format!("não foi possível resolver o caminho: {e}"))?;
    if !canon_roots
        .iter()
        .any(|r| canon != *r && canon.starts_with(r))
    {
        return Err("fora das pastas permitidas".into());
    }
    // Re-check right before deleting to narrow the TOCTOU window.
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() && !is_link_like(&m) => {}
        _ => return Err("o arquivo mudou durante a limpeza".into()),
    }
    fs::remove_file(path).map_err(|e| format!("não foi possível apagar: {e}"))?;
    Ok(meta.len())
}

/// Removes empty directories below `dir` bottom-up. Never follows links and
/// never removes `dir` itself when `is_root`. Returns true if `dir` was removed.
fn prune_empty_dirs(dir: &Path, is_root: bool) -> bool {
    let Ok(rd) = fs::read_dir(dir) else {
        return false;
    };
    let mut empty = true;
    for entry in rd.flatten() {
        let path = entry.path();
        let real_dir = fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir() && !is_link_like(&m));
        if real_dir && prune_empty_dirs(&path, false) {
            continue;
        }
        empty = false;
    }
    if empty && !is_root {
        // remove_dir fails on non-empty directories, which keeps this safe.
        return fs::remove_dir(dir).is_ok();
    }
    false
}
