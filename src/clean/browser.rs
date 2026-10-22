//! Browser cache category (Chrome, Edge, Brave, Firefox). Only the exact cache
//! sub-folders are ever planned; cookies, history, passwords and other profile
//! data are never roots.

use std::fs;
use std::path::{Path, PathBuf};

use super::category::{ApplyReport, Category, Env, Plan, delete_checked, plan_files, safe_root};
use crate::walker::is_link_like;

pub struct BrowserCache {
    /// Receives a process name such as `chrome.exe`.
    pub is_running: fn(&str) -> bool,
}

impl Default for BrowserCache {
    fn default() -> Self {
        BrowserCache {
            is_running: process_running,
        }
    }
}

fn process_running(name: &str) -> bool {
    use sysinfo::{ProcessesToUpdate, System};
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    sys.processes()
        .values()
        .any(|p| p.name().to_string_lossy().eq_ignore_ascii_case(name))
}

struct Browser {
    label: &'static str,
    process: &'static str,
    /// Path of the profile container relative to `local_app_data`.
    base: &'static [&'static str],
    chromium: bool,
}

const BROWSERS: &[Browser] = &[
    Browser {
        label: "Chrome",
        process: "chrome.exe",
        base: &["Google", "Chrome", "User Data"],
        chromium: true,
    },
    Browser {
        label: "Edge",
        process: "msedge.exe",
        base: &["Microsoft", "Edge", "User Data"],
        chromium: true,
    },
    Browser {
        label: "Brave",
        process: "brave.exe",
        base: &["BraveSoftware", "Brave-Browser", "User Data"],
        chromium: true,
    },
    Browser {
        label: "Firefox",
        process: "firefox.exe",
        base: &["Mozilla", "Firefox", "Profiles"],
        chromium: false,
    },
];

const CHROMIUM_CACHE_DIRS: &[&str] = &["Cache", "Code Cache", "GPUCache"];

/// True for a real directory (not a symlink / reparse point).
fn is_plain_dir(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| m.is_dir() && !is_link_like(&m))
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut v: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| is_plain_dir(p))
        .collect();
    v.sort();
    v
}

fn cache_roots(b: &Browser, base: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for profile in subdirs(base) {
        if b.chromium {
            let name = profile
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if name != "Default" && !name.starts_with("Profile ") {
                continue;
            }
            for sub in CHROMIUM_CACHE_DIRS {
                let c = profile.join(sub);
                if is_plain_dir(&c) {
                    out.push(c);
                }
            }
        } else {
            let c = profile.join("cache2");
            if is_plain_dir(&c) {
                out.push(c);
            }
        }
    }
    out
}

impl BrowserCache {
    fn resolved(&self, env: &Env) -> (Vec<PathBuf>, Vec<String>) {
        let mut roots = Vec::new();
        let mut warnings = Vec::new();
        let Some(lad) = env.local_app_data.as_ref() else {
            warnings.push("LOCALAPPDATA não definido; cache de navegadores ignorado".into());
            return (roots, warnings);
        };
        for b in BROWSERS {
            let mut base = lad.clone();
            base.extend(b.base);
            if !is_plain_dir(&base) {
                continue;
            }
            let found = cache_roots(b, &base);
            if found.is_empty() {
                continue;
            }
            if (self.is_running)(b.process) {
                warnings.push(format!("{} está aberto; cache ignorado", b.label));
                continue;
            }
            for r in found {
                if safe_root(&r, env) {
                    roots.push(r);
                } else {
                    warnings.push(format!("pasta insegura descartada: {}", r.display()));
                }
            }
        }
        (roots, warnings)
    }
}

impl Category for BrowserCache {
    fn id(&self) -> &'static str {
        "browser-cache"
    }
    fn needs_admin(&self) -> bool {
        false
    }
    fn roots(&self, env: &Env) -> Vec<PathBuf> {
        self.resolved(env).0
    }
    fn plan(&self, env: &Env) -> Plan {
        let (roots, mut warnings) = self.resolved(env);
        let mut plan = plan_files(&roots, env.use_creation_time, |_| true);
        warnings.append(&mut plan.warnings);
        plan.warnings = warnings;
        plan.min_age = None;
        plan
    }
    fn apply(&self, env: &Env, plan: &Plan) -> ApplyReport {
        delete_checked(&self.roots(env), plan, env.use_creation_time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn env(lad: &Path) -> Env {
        Env {
            temp: None,
            local_app_data: Some(lad.to_path_buf()),
            app_data: None,
            program_data: None,
            system_root: None,
            user_profile: None,
            now: SystemTime::now(),
            elevated: false,
            use_creation_time: false,
        }
    }

    fn touch(p: PathBuf) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, b"data").unwrap();
    }

    fn none_running(_: &str) -> bool {
        false
    }

    fn chrome_running(n: &str) -> bool {
        n == "chrome.exe"
    }

    fn chrome_profile(lad: &Path, profile: &str) -> PathBuf {
        lad.join("Google/Chrome/User Data").join(profile)
    }

    fn names(plan: &Plan) -> Vec<String> {
        let mut v: Vec<String> = plan
            .items
            .iter()
            .map(|c| c.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    fn make_default_profile(lad: &Path) -> PathBuf {
        let d = chrome_profile(lad, "Default");
        touch(d.join("Cache/f1"));
        touch(d.join("Code Cache/f2"));
        touch(d.join("Cookies"));
        touch(d.join("History"));
        touch(d.join("Login Data"));
        touch(d.join("Preferences"));
        touch(d.join("Local Storage/leveldb/000003.log"));
        d
    }

    #[test]
    fn only_cache_dirs_planned() {
        let t = tempfile::tempdir().unwrap();
        make_default_profile(t.path());
        let cat = BrowserCache {
            is_running: none_running,
        };
        let plan = cat.plan(&env(t.path()));
        assert_eq!(names(&plan), vec!["f1", "f2"]);
        assert_eq!(plan.min_age, None);
    }

    #[test]
    fn apply_preserves_cookies_history() {
        let t = tempfile::tempdir().unwrap();
        let d = make_default_profile(t.path());
        let cat = BrowserCache {
            is_running: none_running,
        };
        let e = env(t.path());
        let plan = cat.plan(&e);
        let rep = cat.apply(&e, &plan);
        assert_eq!(rep.deleted, 2);
        assert!(!d.join("Cache/f1").exists());
        assert!(!d.join("Code Cache/f2").exists());
        for keep in [
            "Cookies",
            "History",
            "Login Data",
            "Preferences",
            "Local Storage/leveldb/000003.log",
        ] {
            assert!(d.join(keep).exists(), "{keep} must survive");
        }
    }

    #[test]
    fn profile_glob() {
        let t = tempfile::tempdir().unwrap();
        touch(chrome_profile(t.path(), "Profile 1").join("Cache/x"));
        touch(chrome_profile(t.path(), "Profile 1").join("Cookies"));
        touch(chrome_profile(t.path(), "System Profile").join("Cache/y"));
        let cat = BrowserCache {
            is_running: none_running,
        };
        let plan = cat.plan(&env(t.path()));
        assert_eq!(names(&plan), vec!["x"]);
    }

    #[test]
    fn firefox_cache2() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("Mozilla/Firefox/Profiles/abc.default");
        touch(p.join("cache2/entries/x"));
        touch(p.join("places.sqlite"));
        touch(p.join("cookies.sqlite"));
        let cat = BrowserCache {
            is_running: none_running,
        };
        let plan = cat.plan(&env(t.path()));
        assert_eq!(names(&plan), vec!["x"]);
    }

    #[test]
    fn running_browser_skipped() {
        let t = tempfile::tempdir().unwrap();
        touch(chrome_profile(t.path(), "Default").join("Cache/c"));
        touch(t.path().join("Microsoft/Edge/User Data/Default/Cache/e"));
        let cat = BrowserCache {
            is_running: chrome_running,
        };
        let e = env(t.path());
        let plan = cat.plan(&e);
        assert_eq!(names(&plan), vec!["e"]);
        assert!(plan.warnings.iter().any(|w| w.contains("Chrome")));
        // apply must not delete Chrome files even if a stale plan names them.
        let stale = BrowserCache {
            is_running: none_running,
        }
        .plan(&e);
        let rep = cat.apply(&e, &stale);
        assert!(chrome_profile(t.path(), "Default").join("Cache/c").exists());
        assert_eq!(rep.deleted, 1);
    }

    #[test]
    fn missing_local_app_data_and_traits() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BrowserCache>();
        let mut e = env(Path::new("/nonexistent"));
        e.local_app_data = None;
        let cat = BrowserCache::default();
        assert!(cat.plan(&e).items.is_empty());
        assert_eq!(cat.id(), "browser-cache");
        assert!(!cat.needs_admin());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_cache_dir_ignored() {
        let t = tempfile::tempdir().unwrap();
        let outside = t.path().join("outside");
        touch(outside.join("secret"));
        let prof = chrome_profile(t.path(), "Default");
        fs::create_dir_all(&prof).unwrap();
        std::os::unix::fs::symlink(&outside, prof.join("Cache")).unwrap();
        let cat = BrowserCache {
            is_running: none_running,
        };
        assert!(cat.plan(&env(t.path())).items.is_empty());
    }
}
