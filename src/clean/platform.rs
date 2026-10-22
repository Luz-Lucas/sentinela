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
            let (items, bytes) = match query_recycle_bin() {
                Ok(v) => v,
                Err(e) => {
                    report.skipped.push((PathBuf::from("Lixeira"), e));
                    return report;
                }
            };
            if items == 0 {
                return report;
            }
            match empty_recycle_bin() {
                Ok(()) => {
                    report.deleted = items;
                    report.freed = bytes;
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

/// Coarse state of the Windows Update service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Stopped,
    Running,
    /// Start/stop pending, paused, etc.: the service is not touched.
    Other,
}

fn skip_report(reason: String) -> ApplyReport {
    let mut report = ApplyReport::default();
    report.skipped.push((PathBuf::from(WU_SERVICE), reason));
    report
}

/// Service-aware deletion. Stopped: just delete. Running: stop -> delete ->
/// start; `start` always runs once `stop` succeeded, even if `delete` panics
/// (the panic is re-raised afterwards). If `stop` fails, or the state is
/// pending/unknown/unreadable, nothing is deleted and the service is left alone.
pub fn run_with_service(
    state: impl FnOnce() -> Result<ServiceState, String>,
    stop: impl FnOnce() -> Result<(), String>,
    delete: impl FnOnce() -> ApplyReport,
    start: impl FnOnce() -> Result<(), String>,
) -> ApplyReport {
    match state() {
        Err(e) => {
            return skip_report(format!(
                "não foi possível consultar o serviço Windows Update; nada foi apagado: {e}"
            ));
        }
        Ok(ServiceState::Stopped) => return delete(),
        Ok(ServiceState::Other) => {
            return skip_report(
                "serviço Windows Update em transição (iniciando/parando/pausado); nada foi apagado"
                    .to_string(),
            );
        }
        Ok(ServiceState::Running) => {}
    }
    if let Err(e) = stop() {
        return skip_report(format!(
            "não foi possível parar o serviço Windows Update; nada foi apagado: {e}"
        ));
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
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let detail = [stdout.trim(), stderr.trim()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" | ");
    Err(format!(
        "net {action} {WU_SERVICE} falhou ({}): {detail}",
        out.status
    ))
}

/// Closes an SCM/service handle on drop.
#[cfg(windows)]
struct ScHandle(windows_sys::Win32::System::Services::SC_HANDLE);

#[cfg(windows)]
impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was returned non-null by OpenSCManagerW/OpenServiceW
        // and is closed exactly once.
        unsafe { windows_sys::Win32::System::Services::CloseServiceHandle(self.0) };
    }
}

/// Reads the service state through the SCM (never parses localized text).
#[cfg(windows)]
fn query_service_state() -> Result<ServiceState, String> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Services::{
        OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS,
        SERVICE_RUNNING, SERVICE_STATUS, SERVICE_STOPPED,
    };

    // SAFETY: null machine/database names select the local active database.
    let scm = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        // SAFETY: GetLastError has no preconditions.
        let code = unsafe { GetLastError() };
        return Err(format!("OpenSCManager falhou (erro {code})"));
    }
    let scm = ScHandle(scm);

    let name: Vec<u16> = WU_SERVICE
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `scm.0` is a valid handle and `name` is NUL-terminated UTF-16.
    let svc = unsafe { OpenServiceW(scm.0, name.as_ptr(), SERVICE_QUERY_STATUS) };
    if svc.is_null() {
        // SAFETY: GetLastError has no preconditions.
        let code = unsafe { GetLastError() };
        return Err(format!("OpenService falhou (erro {code})"));
    }
    let svc = ScHandle(svc);

    let mut status = SERVICE_STATUS {
        dwServiceType: 0,
        dwCurrentState: 0,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    // SAFETY: `svc.0` is a valid handle with SERVICE_QUERY_STATUS access and
    // `status` is a valid out-pointer.
    let ok = unsafe { QueryServiceStatus(svc.0, &mut status) };
    if ok == 0 {
        // SAFETY: GetLastError has no preconditions.
        let code = unsafe { GetLastError() };
        return Err(format!("QueryServiceStatus falhou (erro {code})"));
    }
    Ok(match status.dwCurrentState {
        SERVICE_STOPPED => ServiceState::Stopped,
        SERVICE_RUNNING => ServiceState::Running,
        _ => ServiceState::Other,
    })
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
        let mut plan = plan_files(&roots, env.use_creation_time, |_| true);
        warnings.append(&mut plan.warnings);
        plan.warnings = warnings;
        plan
    }
    fn apply(&self, env: &Env, plan: &Plan) -> ApplyReport {
        let roots = self.roots(env);
        let use_creation_time = env.use_creation_time;
        #[cfg(windows)]
        {
            run_with_service(
                query_service_state,
                || net_service("stop"),
                || delete_checked(&roots, plan, use_creation_time),
                || net_service("start"),
            )
        }
        #[cfg(not(windows))]
        {
            delete_checked(&roots, plan, use_creation_time)
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
            use_creation_time: false,
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
        let rep = delete_checked(&WindowsUpdate.roots(&env), &plan, env.use_creation_time);
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

    /// Records the order in which the service closures are invoked.
    fn run(
        state: Result<ServiceState, String>,
        stop: Result<(), String>,
        delete: impl FnOnce() -> ApplyReport,
        start: Result<(), String>,
    ) -> (ApplyReport, Vec<&'static str>) {
        let log = std::cell::RefCell::new(Vec::new());
        let rep = run_with_service(
            || state,
            || {
                log.borrow_mut().push("stop");
                stop
            },
            || {
                log.borrow_mut().push("delete");
                delete()
            },
            || {
                log.borrow_mut().push("start");
                start
            },
        );
        (rep, log.into_inner())
    }

    fn deleted(n: u64) -> ApplyReport {
        ApplyReport {
            deleted: n,
            ..ApplyReport::default()
        }
    }

    #[test]
    fn stopped_service_deletes_without_stop_or_start() {
        let (rep, log) = run(Ok(ServiceState::Stopped), Ok(()), || deleted(2), Ok(()));
        assert_eq!(log, vec!["delete"]);
        assert_eq!(rep.deleted, 2);
        assert!(rep.skipped.is_empty());
    }

    #[test]
    fn running_service_stop_delete_start_in_order() {
        let (rep, log) = run(Ok(ServiceState::Running), Ok(()), || deleted(1), Ok(()));
        assert_eq!(log, vec!["stop", "delete", "start"]);
        assert_eq!(rep.deleted, 1);
        assert!(rep.skipped.is_empty());
    }

    #[test]
    fn other_state_touches_nothing() {
        let (rep, log) = run(Ok(ServiceState::Other), Ok(()), || deleted(1), Ok(()));
        assert!(log.is_empty());
        assert_eq!(rep.deleted, 0);
        assert_eq!(rep.skipped.len(), 1);
    }

    #[test]
    fn query_error_touches_nothing() {
        let (rep, log) = run(Err("acesso negado".into()), Ok(()), || deleted(1), Ok(()));
        assert!(log.is_empty());
        assert_eq!(rep.skipped.len(), 1);
        assert!(rep.skipped[0].1.contains("acesso negado"));
    }

    #[test]
    fn stop_failure_skips_delete_and_start() {
        let (rep, log) = run(
            Ok(ServiceState::Running),
            Err("negado".into()),
            || deleted(1),
            Ok(()),
        );
        assert_eq!(log, vec!["stop"]);
        assert_eq!(rep.skipped.len(), 1);
        assert!(rep.skipped[0].1.contains("negado"));
    }

    #[test]
    fn start_runs_even_when_delete_fails() {
        let (rep, log) = run(
            Ok(ServiceState::Running),
            Ok(()),
            || {
                let mut r = ApplyReport::default();
                r.skipped.push((PathBuf::from("x"), "falhou".into()));
                r
            },
            Ok(()),
        );
        assert_eq!(log, vec!["stop", "delete", "start"]);
        assert_eq!(rep.skipped.len(), 1);
    }

    #[test]
    fn start_runs_even_when_delete_panics() {
        let started = Cell::new(false);
        let res = catch_unwind(AssertUnwindSafe(|| {
            run_with_service(
                || Ok(ServiceState::Running),
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
    fn start_failure_is_reported() {
        let (rep, _) = run(
            Ok(ServiceState::Running),
            Ok(()),
            || deleted(3),
            Err("sem acesso".into()),
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
