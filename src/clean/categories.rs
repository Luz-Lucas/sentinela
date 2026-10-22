//! Temp-file and crash-dump categories.

use std::path::PathBuf;
use std::time::Duration;

use super::category::{
    ApplyReport, Category, Env, Plan, delete_checked, effective_age, plan_files, safe_root,
};

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
    let mut plan = plan_files(roots, env.use_creation_time, |e| {
        effective_age(e.modified, e.created, now).is_some_and(|age| age > MIN_AGE)
    });
    plan.min_age = Some(MIN_AGE);
    finish(plan, warnings)
}

pub struct UserTemp;

impl UserTemp {
    fn resolved(env: &Env) -> (Vec<PathBuf>, Vec<String>) {
        fn is_temp_name(p: &std::path::Path) -> bool {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.eq_ignore_ascii_case("temp") || n.eq_ignore_ascii_case("tmp"))
        }
        // Both the raw and (when it exists) the canonical name must be Temp/Tmp,
        // so a `Temp` junction pointing at Documents is refused.
        let temp_named = env.temp.as_ref().is_none_or(|t| {
            is_temp_name(t) && std::fs::canonicalize(t).map_or(true, |c| is_temp_name(&c))
        });
        if !temp_named {
            let shown = env.temp.as_ref().map(|t| t.display().to_string());
            return (
                Vec::new(),
                vec![format!(
                    "pasta TEMP não se chama Temp/Tmp; descartada: {}",
                    shown.unwrap_or_default()
                )],
            );
        }
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
        delete_checked(&self.roots(env), plan, env.use_creation_time)
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
        delete_checked(&self.roots(env), plan, env.use_creation_time)
    }
}

pub struct CrashDumps;

impl CrashDumps {
    /// The system-wide roots (Minidump, WER archives) need elevation.
    fn resolved(env: &Env) -> (Vec<PathBuf>, Vec<String>) {
        let mut candidates = vec![(
            "LOCALAPPDATA",
            env.local_app_data.as_ref().map(|p| p.join("CrashDumps")),
        )];
        let mut extra = Vec::new();
        if env.elevated {
            let wer = env
                .program_data
                .as_ref()
                .map(|p| p.join("Microsoft").join("Windows").join("WER"));
            candidates.push((
                "SystemRoot",
                env.system_root.as_ref().map(|p| p.join("Minidump")),
            ));
            candidates.push(("ProgramData", wer.as_ref().map(|p| p.join("ReportArchive"))));
            candidates.push(("ProgramData", wer.as_ref().map(|p| p.join("ReportQueue"))));
        } else {
            extra.push(
                "Minidump e relatórios WER do sistema: requer administrador; ignorados".to_string(),
            );
        }
        let (roots, mut warnings) = resolve_roots(env, candidates);
        warnings.extend(extra);
        (roots, warnings)
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
        finish(
            plan_files(&roots, env.use_creation_time, |_| true),
            warnings,
        )
    }
    fn apply(&self, env: &Env, plan: &Plan) -> ApplyReport {
        delete_checked(&self.roots(env), plan, env.use_creation_time)
    }
}
