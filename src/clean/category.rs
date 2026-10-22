//! Cleaning core: the `Category` trait, root safety checks and checked deletion.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::Serialize;

use crate::walker::{Entry, WalkItem, WalkOptions, created_of, is_link_like, walk};

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
    /// Whether the process is elevated. `from_system` sets false; the CLI sets
    /// it from its elevation check (`run_clean` also overrides it).
    pub elevated: bool,
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
            elevated: false,
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
    /// If set, files modified more recently than this are skipped at delete time.
    #[serde(skip)]
    pub min_age: Option<Duration>,
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

/// Age of a file as `now - max(modified, created)`; `created` is ignored when
/// unavailable. `None` when the newest timestamp is in the future.
pub fn effective_age(
    modified: SystemTime,
    created: Option<SystemTime>,
    now: SystemTime,
) -> Option<Duration> {
    let newest = created.map_or(modified, |c| c.max(modified));
    now.duration_since(newest).ok()
}

/// Canonical form when the path exists, otherwise the path as given.
fn normalize(p: &Path) -> PathBuf {
    fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// False for drive roots, "/", and any of the user profile, system root,
/// LOCALAPPDATA, APPDATA, ProgramData or an ancestor of them.
pub fn safe_root(p: &Path, env: &Env) -> bool {
    if p.as_os_str().is_empty() || p.parent().is_none() {
        return false;
    }
    let norm = normalize(p);
    if norm.parent().is_none() {
        return false;
    }
    for protected in [
        &env.user_profile,
        &env.system_root,
        &env.local_app_data,
        &env.app_data,
        &env.program_data,
    ]
    .into_iter()
    .flatten()
    {
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
    let opts = WalkOptions {
        strict_links: true,
        ..WalkOptions::default()
    };
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
    let mut deleted_paths = Vec::new();

    for cand in &plan.items {
        let path = &cand.path;
        match delete_one(path, &canon_roots, plan.min_age) {
            Ok((canon, size)) => {
                report.deleted += 1;
                report.freed += size;
                deleted_paths.push(canon);
            }
            Err(reason) => report.skipped.push((path.clone(), reason)),
        }
    }

    // Only ancestors of files deleted in this run are pruned, bottom-up.
    for canon in &deleted_paths {
        let Some(root) = canon_roots.iter().find(|r| canon.starts_with(r)) else {
            continue;
        };
        let mut dir = canon.parent();
        while let Some(d) = dir {
            if d == root.as_path() || !d.starts_with(root) {
                break;
            }
            // remove_dir fails on non-empty directories, which keeps this safe.
            if fs::remove_dir(d).is_err() {
                break;
            }
            dir = d.parent();
        }
    }
    report
}

fn inside_roots(canon: &Path, canon_roots: &[PathBuf]) -> bool {
    canon_roots
        .iter()
        .any(|r| canon != r.as_path() && canon.starts_with(r))
}

fn delete_one(
    path: &Path,
    canon_roots: &[PathBuf],
    min_age: Option<Duration>,
) -> Result<(PathBuf, u64), String> {
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
    if !inside_roots(&canon, canon_roots) {
        return Err("fora das pastas permitidas".into());
    }
    // Re-validate immediately before deleting and delete the canonical path.
    // Residual race: handle-based deletion (FILE_FLAG_OPEN_REPARSE_POINT) is a follow-up.
    let canon =
        fs::canonicalize(&canon).map_err(|_| "o arquivo mudou durante a limpeza".to_string())?;
    if !inside_roots(&canon, canon_roots) {
        return Err("fora das pastas permitidas".into());
    }
    let meta = match fs::symlink_metadata(&canon) {
        Ok(m) if m.is_file() && !is_link_like(&m) => m,
        _ => return Err("o arquivo mudou durante a limpeza".into()),
    };
    if let Some(min) = min_age {
        let old_enough = meta
            .modified()
            .ok()
            .and_then(|m| effective_age(m, created_of(&meta), SystemTime::now()))
            .is_some_and(|age| age > min);
        if !old_enough {
            return Err("arquivo modificado recentemente".into());
        }
    }
    fs::remove_file(&canon).map_err(|e| format!("não foi possível apagar: {e}"))?;
    Ok((canon, meta.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_age_uses_the_most_recent_timestamp() {
        let now = SystemTime::now();
        let old = now - Duration::from_secs(10 * 24 * 3600);
        let recent = now - Duration::from_secs(60);
        // Old mtime but recent creation (e.g. an extracted archive): young.
        assert_eq!(
            effective_age(old, Some(recent), now),
            Some(Duration::from_secs(60))
        );
        // Created long ago, modified recently: young as well.
        assert_eq!(
            effective_age(recent, Some(old), now),
            Some(Duration::from_secs(60))
        );
        // No creation time available: falls back to modified.
        assert_eq!(
            effective_age(old, None, now),
            Some(Duration::from_secs(10 * 24 * 3600))
        );
        // Timestamps in the future: unknown age, never "old".
        assert_eq!(
            effective_age(now + Duration::from_secs(60), None, now),
            None
        );
    }
}
