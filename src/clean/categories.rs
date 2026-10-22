//! Temp-file and crash-dump categories.

use std::path::PathBuf;
use std::time::Duration;

use super::category::{ApplyReport, Category, Env, Plan, delete_checked, plan_files, safe_root};

/// Temporary files younger than this are never touched.
pub const MIN_AGE: Duration = Duration::from_secs(24 * 3600);

/// Applies `safe_root` to candidate roots (`None` means the env var is
/// missing). Missing directories are ignored silently.
fn resolve_roots(
    env: &Env,
    candidates: Vec<(&str, Option<PathBuf>)>,
) -> (Vec<PathBuf>, Vec<String>) {
    let mut roots = Vec::new();
    let mut warnings = Vec::new();
    for (label, cand) in candidates {
        let Some(path) = cand else {
            warnings.push(format!("{label} não definido; pasta ignorada"));
            continue;
        };
        if !safe_root(&path, env) {
            warnings.push(format!("pasta insegura descartada: {}", path.display()));
            continue;
        }
        if path.is_dir() {
            roots.push(path);
        }
    }
    (roots, warnings)
}

fn finish(mut plan: Plan, mut warnings: Vec<String>) -> Plan {
    warnings.append(&mut plan.warnings);
    plan.warnings = warnings;
    plan
}

fn plan_old(env: &Env, roots: &[PathBuf], warnings: Vec<String>) -> Plan {
    let now = env.now;
    let plan = plan_files(roots, |e| {
        now.duration_since(e.modified)
            .is_ok_and(|age| age > MIN_AGE)
    });
    finish(plan, warnings)
}

pub struct UserTemp;

impl UserTemp {
    fn resolved(env: &Env) -> (Vec<PathBuf>, Vec<String>) {
        resolve_roots(env, vec![("TEMP", env.temp.clone())])
    }
}

impl Category for UserTemp {
    fn id(&self) -> &'static str {
        "user-temp"
    }
    fn needs_admin(&self) -> bool {
        false
    }
    fn roots(&self, env: &Env) -> Vec<PathBuf> {
        Self::resolved(env).0
    }
    fn plan(&self, env: &Env) -> Plan {
        let (roots, warnings) = Self::resolved(env);
        plan_old(env, &roots, warnings)
    }
    fn apply(&self, env: &Env, plan: &Plan) -> ApplyReport {
        delete_checked(&self.roots(env), plan)
    }
}

pub struct WindowsTemp;

impl WindowsTemp {
    fn resolved(env: &Env) -> (Vec<PathBuf>, Vec<String>) {
        let root = env.system_root.as_ref().map(|r| r.join("Temp"));
        resolve_roots(env, vec![("SystemRoot", root)])
    }
}

impl Category for WindowsTemp {
    fn id(&self) -> &'static str {
        "windows-temp"
    }
    fn needs_admin(&self) -> bool {
        true
    }
    fn roots(&self, env: &Env) -> Vec<PathBuf> {
        Self::resolved(env).0
    }
    fn plan(&self, env: &Env) -> Plan {
        let (roots, warnings) = Self::resolved(env);
        plan_old(env, &roots, warnings)
    }
    fn apply(&self, env: &Env, plan: &Plan) -> ApplyReport {
        delete_checked(&self.roots(env), plan)
    }
}

pub struct CrashDumps;

impl CrashDumps {
    /// The system-wide roots (Minidump, WER archives) are always listed; files
    /// there that a non-admin cannot delete end up in `skipped`.
    fn resolved(env: &Env) -> (Vec<PathBuf>, Vec<String>) {
        let wer = env
            .program_data
            .as_ref()
            .map(|p| p.join("Microsoft").join("Windows").join("WER"));
        resolve_roots(
            env,
            vec![
                (
                    "LOCALAPPDATA",
                    env.local_app_data.as_ref().map(|p| p.join("CrashDumps")),
                ),
                (
                    "SystemRoot",
                    env.system_root.as_ref().map(|p| p.join("Minidump")),
                ),
                ("ProgramData", wer.as_ref().map(|p| p.join("ReportArchive"))),
                ("ProgramData", wer.as_ref().map(|p| p.join("ReportQueue"))),
            ],
        )
    }
}

impl Category for CrashDumps {
    fn id(&self) -> &'static str {
        "crash-dumps"
    }
    fn needs_admin(&self) -> bool {
        false
    }
    fn roots(&self, env: &Env) -> Vec<PathBuf> {
        Self::resolved(env).0
    }
    fn plan(&self, env: &Env) -> Plan {
        let (roots, warnings) = Self::resolved(env);
        finish(plan_files(&roots, |_| true), warnings)
    }
    fn apply(&self, env: &Env, plan: &Plan) -> ApplyReport {
        delete_checked(&self.roots(env), plan)
    }
}
