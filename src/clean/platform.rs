//! Windows-specific pieces: elevation check, Recycle Bin and Windows Update cache.

use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::PathBuf;

use super::category::{ApplyReport, Category, Env, Plan, delete_checked, plan_files, safe_root};

/// True when the process runs with administrator rights (Windows only).
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        // SAFETY: IsUserAnAdmin takes no arguments and has no preconditions.
        unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(windows)]
fn query_recycle_bin() -> Result<(u64, u64), String> {
    use windows_sys::Win32::UI::Shell::{SHQUERYRBINFO, SHQueryRecycleBinW};

    let mut info = SHQUERYRBINFO {
        cbSize: std::mem::size_of::<SHQUERYRBINFO>() as u32,
        i64Size: 0,
        i64NumItems: 0,
    };
    // SAFETY: a null root path queries all drives; `info` is a valid, initialised
    // SHQUERYRBINFO with cbSize set, as the API requires.
    let hr = unsafe { SHQueryRecycleBinW(std::ptr::null(), &mut info) };
    if hr < 0 {
        return Err(format!("falha ao consultar a Lixeira (HRESULT 0x{hr:08X})"));
    }
    Ok((info.i64NumItems.max(0) as u64, info.i64Size.max(0) as u64))
}

#[cfg(windows)]
fn empty_recycle_bin() -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::{
        SHERB_NOCONFIRMATION, SHERB_NOPROGRESSUI, SHERB_NOSOUND, SHEmptyRecycleBinW,
    };

    // SAFETY: null window handle and null root path (all drives) are documented
    // as valid for SHEmptyRecycleBinW.
    let hr = unsafe {
        SHEmptyRecycleBinW(
            std::ptr::null_mut(),
            std::ptr::null(),
            SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND,
        )
    };
    if hr < 0 {
        return Err(format!("falha ao esvaziar a Lixeira (HRESULT 0x{hr:08X})"));
    }
    Ok(())
}

pub struct RecycleBin;

impl Category for RecycleBin {
    fn id(&self) -> &'static str {
        "recycle-bin"
    }
    fn needs_admin(&self) -> bool {
        false
    }
    fn roots(&self, _env: &Env) -> Vec<PathBuf> {
        Vec::new()
    }
    fn plan(&self, _env: &Env) -> Plan {
        #[cfg(windows)]
        {
            match query_recycle_bin() {
                Ok((files, bytes)) => Plan {
                    files,
                    bytes,
                    ..Plan::default()
                },
                Err(e) => Plan {
                    warnings: vec![e],
                    ..Plan::default()
                },
            }
        }
        #[cfg(not(windows))]
        {
            Plan {
                warnings: vec!["disponível só no Windows".to_string()],
                ..Plan::default()
            }
        }
    }
    fn apply(&self, _env: &Env, _plan: &Plan) -> ApplyReport {
        #[cfg(windows)]
        {
            let mut report = ApplyReport::default();
            // Measured right before emptying so the report reflects what was removed.
            let before = query_recycle_bin().unwrap_or((0, 0));
            match empty_recycle_bin() {
                Ok(()) => {
                    report.deleted = before.0;
                    report.freed = before.1;
                }
                Err(e) => report.skipped.push((PathBuf::from("Lixeira"), e)),
            }
            report
        }
        #[cfg(not(windows))]
        {
            ApplyReport::default()
        }
    }
}

const WU_SERVICE: &str = "wuauserv";

/// Stop -> delete -> start. `start` always runs once `stop` succeeded, even if
/// `delete` panics (the panic is re-raised afterwards). If `stop` fails nothing
/// is deleted (files may be in use) and `start` is not called.
pub fn with_service_stopped(
    stop: impl FnOnce() -> Result<(), String>,
    delete: impl FnOnce() -> ApplyReport,
    start: impl FnOnce() -> Result<(), String>,
) -> ApplyReport {
    if let Err(e) = stop() {
        let mut report = ApplyReport::default();
        report.skipped.push((
            PathBuf::from(WU_SERVICE),
            format!("não foi possível parar o serviço Windows Update; nada foi apagado: {e}"),
        ));
        return report;
    }
    let outcome = catch_unwind(AssertUnwindSafe(delete));
    let started = start();
    let mut report = match outcome {
        Ok(r) => r,
        Err(panic) => resume_unwind(panic),
    };
    if let Err(e) = started {
        report.skipped.push((
            PathBuf::from(WU_SERVICE),
            format!("não foi possível reiniciar o serviço Windows Update: {e}"),
        ));
    }
    report
}

#[cfg(windows)]
fn net_service(action: &str) -> Result<(), String> {
    let out = std::process::Command::new("net")
        .args([action, WU_SERVICE])
        .output()
        .map_err(|e| format!("net {action} {WU_SERVICE}: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let detail = text.trim();
    Err(format!(
        "net {action} {WU_SERVICE} falhou ({}): {detail}",
        out.status
    ))
}

pub struct WindowsUpdate;

impl WindowsUpdate {
    fn resolved(env: &Env) -> (Vec<PathBuf>, Vec<String>) {
        let Some(sys) = env.system_root.as_ref() else {
            return (
                Vec::new(),
                vec!["SystemRoot não definido; pasta ignorada".into()],
            );
        };
        let root = sys.join("SoftwareDistribution").join("Download");
        if !safe_root(&root, env) {
            return (
                Vec::new(),
                vec![format!("pasta insegura descartada: {}", root.display())],
            );
        }
        if root.is_dir() {
            (vec![root], Vec::new())
        } else {
            (Vec::new(), Vec::new())
        }
    }
}

impl Category for WindowsUpdate {
    fn id(&self) -> &'static str {
        "windows-update"
    }
    fn needs_admin(&self) -> bool {
        true
    }
    fn roots(&self, env: &Env) -> Vec<PathBuf> {
        Self::resolved(env).0
    }
    fn plan(&self, env: &Env) -> Plan {
        let (roots, mut warnings) = Self::resolved(env);
        let mut plan = plan_files(&roots, |_| true);
        warnings.append(&mut plan.warnings);
        plan.warnings = warnings;
        plan
    }
    fn apply(&self, env: &Env, plan: &Plan) -> ApplyReport {
        let roots = self.roots(env);
        #[cfg(windows)]
        {
            with_service_stopped(
                || net_service("stop"),
                || delete_checked(&roots, plan),
                || net_service("start"),
            )
        }
        #[cfg(not(windows))]
        {
            delete_checked(&roots, plan)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fs;
    use std::time::SystemTime;

    fn env_in(base: &std::path::Path) -> Env {
        let sysroot = base.join("windows");
        fs::create_dir_all(&sysroot).unwrap();
        Env {
            temp: None,
            local_app_data: None,
            app_data: None,
            program_data: None,
            system_root: Some(sysroot),
            user_profile: Some(base.join("profile")),
            now: SystemTime::now(),
            elevated: true,
        }
    }

    #[test]
    fn windows_update_plan_uses_download_dir() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let sd = env
            .system_root
            .clone()
            .unwrap()
            .join("SoftwareDistribution");
        fs::create_dir_all(sd.join("Download/sub")).unwrap();
        fs::create_dir_all(sd.join("DataStore")).unwrap();
        fs::write(sd.join("Download/a.cab"), b"abcd").unwrap();
        fs::write(sd.join("Download/sub/b.bin"), b"xy").unwrap();
        fs::write(sd.join("DataStore/db.edb"), b"keep").unwrap();
        let plan = WindowsUpdate.plan(&env);
        assert_eq!(plan.files, 2);
        assert_eq!(plan.bytes, 6);
        assert!(
            plan.items
                .iter()
                .all(|c| c.path.starts_with(sd.join("Download")))
        );
        assert!(WindowsUpdate.needs_admin());
        assert_eq!(WindowsUpdate.id(), "windows-update");
    }

    #[test]
    fn windows_update_apply_deletes_only_download() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let sd = env
            .system_root
            .clone()
            .unwrap()
            .join("SoftwareDistribution");
        fs::create_dir_all(sd.join("Download")).unwrap();
        fs::create_dir_all(sd.join("DataStore")).unwrap();
        fs::write(sd.join("Download/a.cab"), b"abcd").unwrap();
        fs::write(sd.join("DataStore/db.edb"), b"keep").unwrap();
        let plan = WindowsUpdate.plan(&env);
        // Service control only runs on Windows; test the delete path directly.
        let rep = delete_checked(&WindowsUpdate.roots(&env), &plan);
        assert_eq!(rep.deleted, 1);
        assert!(!sd.join("Download/a.cab").exists());
        assert!(sd.join("DataStore/db.edb").exists());
    }

    #[test]
    fn windows_update_missing_dir_is_empty() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        assert_eq!(WindowsUpdate.plan(&env).files, 0);
        let mut e = env;
        e.system_root = None;
        let p = WindowsUpdate.plan(&e);
        assert_eq!(p.files, 0);
        assert!(!p.warnings.is_empty());
    }

    #[test]
    fn start_runs_even_when_delete_fails() {
        let started = Cell::new(false);
        let rep = with_service_stopped(
            || Ok(()),
            || {
                let mut r = ApplyReport::default();
                r.skipped.push((PathBuf::from("x"), "falhou".into()));
                r
            },
            || {
                started.set(true);
                Ok(())
            },
        );
        assert!(started.get());
        assert_eq!(rep.skipped.len(), 1);
    }

    #[test]
    fn start_runs_even_when_delete_panics() {
        let started = Cell::new(false);
        let res = catch_unwind(AssertUnwindSafe(|| {
            with_service_stopped(
                || Ok(()),
                || panic!("boom"),
                || {
                    started.set(true);
                    Ok(())
                },
            )
        }));
        assert!(res.is_err());
        assert!(started.get());
    }

    #[test]
    fn stop_failure_skips_delete_and_start() {
        let deleted = Cell::new(false);
        let started = Cell::new(false);
        let rep = with_service_stopped(
            || Err("negado".into()),
            || {
                deleted.set(true);
                ApplyReport::default()
            },
            || {
                started.set(true);
                Ok(())
            },
        );
        assert!(!deleted.get());
        assert!(!started.get());
        assert_eq!(rep.skipped.len(), 1);
        assert!(rep.skipped[0].1.contains("negado"));
    }

    #[test]
    fn start_failure_is_reported() {
        let rep = with_service_stopped(
            || Ok(()),
            || ApplyReport {
                deleted: 3,
                ..ApplyReport::default()
            },
            || Err("sem acesso".into()),
        );
        assert_eq!(rep.deleted, 3);
        assert_eq!(rep.skipped.len(), 1);
        assert!(rep.skipped[0].1.contains("sem acesso"));
    }

    #[cfg(not(windows))]
    #[test]
    fn is_elevated_false_off_windows() {
        assert!(!is_elevated());
    }

    #[cfg(not(windows))]
    #[test]
    fn recycle_bin_off_windows_is_empty_with_warning() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let p = RecycleBin.plan(&env);
        assert_eq!(p.files, 0);
        assert_eq!(p.warnings, vec!["disponível só no Windows".to_string()]);
        let rep = RecycleBin.apply(&env, &p);
        assert_eq!(rep.deleted, 0);
        assert!(rep.skipped.is_empty());
        assert_eq!(RecycleBin.id(), "recycle-bin");
        assert!(!RecycleBin.needs_admin());
    }

    #[cfg(windows)]
    #[test]
    fn recycle_bin_query_does_not_panic() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let _ = RecycleBin.plan(&env);
    }
}
