pub mod browser;
pub mod categories;
pub mod category;
pub mod platform;

use serde::Serialize;

use category::{ApplyReport, Category, Env, Plan};

#[derive(Serialize)]
pub struct CategoryResult {
    pub id: String,
    pub plan: Plan,
    pub applied: Option<ApplyReport>,
    pub skipped_reason: Option<String>,
}

#[derive(Serialize)]
pub struct CleanReport {
    pub categories: Vec<CategoryResult>,
}

/// All categories, in spec order.
pub fn all_categories() -> Vec<Box<dyn Category>> {
    vec![
        Box::new(categories::UserTemp),
        Box::new(categories::WindowsTemp),
        Box::new(categories::CrashDumps),
        Box::new(browser::BrowserCache::default()),
        Box::new(platform::RecycleBin),
        Box::new(platform::WindowsUpdate),
    ]
}

/// Plans every selected category (empty `selected` means all). Only when
/// `apply` is set, and `confirm` approves the full report once, are files
/// deleted. Admin categories are skipped when not `elevated`.
pub fn run_clean(
    env: &Env,
    cats: &[Box<dyn Category>],
    selected: &[String],
    apply: bool,
    elevated: bool,
    confirm: &mut dyn FnMut(&CleanReport) -> bool,
) -> CleanReport {
    let mut env = env.clone();
    env.elevated = elevated;
    let env = &env;
    let chosen: Vec<&Box<dyn Category>> = cats
        .iter()
        .filter(|c| selected.is_empty() || selected.iter().any(|s| s == c.id()))
        .collect();

    let mut report = CleanReport {
        categories: Vec::new(),
    };
    let mut runnable = Vec::new();
    for cat in &chosen {
        if cat.needs_admin() && !elevated {
            report.categories.push(CategoryResult {
                id: cat.id().to_string(),
                plan: Plan::default(),
                applied: None,
                skipped_reason: Some("requer administrador".to_string()),
            });
            runnable.push(false);
        } else {
            report.categories.push(CategoryResult {
                id: cat.id().to_string(),
                plan: cat.plan(env),
                applied: None,
                skipped_reason: None,
            });
            runnable.push(true);
        }
    }

    let total: u64 = report.categories.iter().map(|c| c.plan.files).sum();
    if apply && total > 0 {
        if confirm(&report) {
            for ((cat, result), ok) in chosen
                .iter()
                .zip(report.categories.iter_mut())
                .zip(runnable)
            {
                if ok {
                    result.applied = Some(cat.apply(env, &result.plan));
                }
            }
        } else {
            for (result, ok) in report.categories.iter_mut().zip(runnable) {
                if ok {
                    result.skipped_reason = Some("cancelado pelo usuário".to_string());
                }
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::categories::{CrashDumps, MIN_AGE, UserTemp, WindowsTemp};
    use super::category::{Candidate, delete_checked, safe_root};
    use super::*;
    use std::fs::{self, File};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    fn env_in(base: &Path) -> Env {
        let profile = base.join("profile");
        let temp = base.join("temp");
        let sysroot = base.join("windows");
        for d in [&profile, &temp, &sysroot.join("Temp")] {
            fs::create_dir_all(d).unwrap();
        }
        Env {
            temp: Some(temp),
            local_app_data: Some(profile.join("AppData")),
            app_data: None,
            program_data: Some(base.join("pdata")),
            system_root: Some(sysroot),
            user_profile: Some(profile),
            now: SystemTime::now(),
            elevated: false,
        }
    }

    fn write_aged(path: &Path, bytes: &[u8], age: Duration) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
        let f = File::options().write(true).open(path).unwrap();
        f.set_modified(SystemTime::now() - age).unwrap();
    }

    fn two_days() -> Duration {
        Duration::from_secs(2 * 24 * 3600)
    }

    fn user_temp() -> Vec<Box<dyn Category>> {
        vec![Box::new(UserTemp)]
    }

    #[test]
    fn plan_never_deletes() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let t = env.temp.clone().unwrap();
        write_aged(&t.join("old1.tmp"), b"aaaa", two_days());
        write_aged(&t.join("sub/old2.tmp"), b"bb", two_days());
        write_aged(&t.join("new.tmp"), b"c", Duration::from_secs(60));
        let rep = run_clean(&env, &user_temp(), &[], false, false, &mut |_| {
            panic!("confirm must not be called without apply")
        });
        assert_eq!(rep.categories.len(), 1);
        let plan = &rep.categories[0].plan;
        assert_eq!(plan.files, 2);
        assert_eq!(plan.bytes, 6);
        assert!(rep.categories[0].applied.is_none());
        assert!(t.join("old1.tmp").exists());
        assert!(t.join("sub/old2.tmp").exists());
        assert!(t.join("new.tmp").exists());
    }

    #[test]
    fn apply_deletes_only_old_files() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let t = env.temp.clone().unwrap();
        write_aged(&t.join("old.tmp"), b"old", two_days());
        write_aged(&t.join("new.tmp"), b"new", MIN_AGE / 2);
        let rep = run_clean(&env, &user_temp(), &[], true, false, &mut |_| true);
        assert!(!t.join("old.tmp").exists());
        assert!(t.join("new.tmp").exists());
        let applied = rep.categories[0].applied.as_ref().unwrap();
        assert_eq!(applied.deleted, 1);
        assert_eq!(applied.freed, 3);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_blocked() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let t = env.temp.clone().unwrap();
        let outside = d.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        write_aged(&outside.join("secret.txt"), b"s", two_days());
        std::os::unix::fs::symlink(outside.join("secret.txt"), t.join("filelink")).unwrap();
        std::os::unix::fs::symlink(&outside, t.join("dirlink")).unwrap();
        run_clean(&env, &user_temp(), &[], true, false, &mut |_| true);
        assert!(outside.join("secret.txt").exists());
        assert!(fs::symlink_metadata(t.join("dirlink")).is_ok());
        // A forged candidate going through the directory link is refused too.
        let plan = Plan {
            items: vec![Candidate {
                path: t.join("dirlink/secret.txt"),
                size: 1,
            }],
            ..Plan::default()
        };
        let rep = delete_checked(std::slice::from_ref(&t), &plan);
        assert_eq!(rep.deleted, 0);
        assert_eq!(rep.skipped.len(), 1);
        assert!(outside.join("secret.txt").exists());
    }

    #[test]
    fn candidate_outside_roots_refused() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let t = env.temp.clone().unwrap();
        let victim = d.path().join("profile/important.doc");
        write_aged(&victim, b"keep", two_days());
        let plan = Plan {
            items: vec![
                Candidate {
                    path: victim.clone(),
                    size: 4,
                },
                Candidate {
                    path: t.join("../profile/important.doc"),
                    size: 4,
                },
            ],
            files: 2,
            bytes: 8,
            warnings: vec![],
            min_age: None,
        };
        let rep = delete_checked(&[t], &plan);
        assert_eq!(rep.deleted, 0);
        assert_eq!(rep.skipped.len(), 2);
        assert!(victim.exists());
    }

    #[test]
    fn dangerous_temp_refused() {
        let d = tempfile::tempdir().unwrap();
        let base = env_in(d.path());

        let mut e = base.clone();
        e.temp = Some(PathBuf::from(std::path::MAIN_SEPARATOR_STR));
        let p = UserTemp.plan(&e);
        assert_eq!(p.files, 0);
        assert!(!p.warnings.is_empty());

        let mut e = base.clone();
        e.temp = e.user_profile.clone();
        write_aged(&e.temp.clone().unwrap().join("doc.txt"), b"x", two_days());
        let p = UserTemp.plan(&e);
        assert_eq!(p.files, 0);
        assert!(!p.warnings.is_empty());

        let mut e = base.clone();
        e.temp = Some(d.path().to_path_buf()); // ancestor of the profile
        let p = UserTemp.plan(&e);
        assert_eq!(p.files, 0);
        assert!(!p.warnings.is_empty());

        let mut e = base.clone();
        e.temp = e.system_root.clone();
        assert_eq!(UserTemp.plan(&e).files, 0);

        let mut e = base;
        e.temp = None;
        let p = UserTemp.plan(&e);
        assert_eq!(p.files, 0);
        assert!(!p.warnings.is_empty());
        assert!(!safe_root(Path::new("/"), &e));
    }

    #[test]
    fn admin_categories_skipped_when_not_elevated() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let wt = env.system_root.clone().unwrap().join("Temp");
        write_aged(&wt.join("x.tmp"), b"x", two_days());
        let cats: Vec<Box<dyn Category>> = vec![Box::new(WindowsTemp)];
        let rep = run_clean(&env, &cats, &[], true, false, &mut |_| true);
        assert!(rep.categories[0].skipped_reason.is_some());
        assert!(rep.categories[0].applied.is_none());
        assert!(wt.join("x.tmp").exists());
        let rep = run_clean(&env, &cats, &[], true, true, &mut |_| true);
        assert!(rep.categories[0].skipped_reason.is_none());
        assert!(!wt.join("x.tmp").exists());
    }

    #[test]
    fn confirm_false_aborts_apply() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let t = env.temp.clone().unwrap();
        write_aged(&t.join("old.tmp"), b"old", two_days());
        let mut calls = 0;
        let rep = run_clean(&env, &user_temp(), &[], true, false, &mut |_| {
            calls += 1;
            false
        });
        assert_eq!(calls, 1);
        assert!(t.join("old.tmp").exists());
        assert!(rep.categories[0].applied.is_none());
    }

    #[test]
    fn empty_subdirs_removed_root_kept() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let t = env.temp.clone().unwrap();
        write_aged(&t.join("a/b/c/old.tmp"), b"o", two_days());
        write_aged(&t.join("a/keep/new.tmp"), b"n", Duration::from_secs(5));
        run_clean(&env, &user_temp(), &[], true, false, &mut |_| true);
        assert!(t.exists());
        assert!(!t.join("a/b").exists());
        assert!(t.join("a/keep/new.tmp").exists());
    }

    #[test]
    fn crash_dumps_take_all_ages_and_selection_filters() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let cd = env.local_app_data.clone().unwrap().join("CrashDumps");
        write_aged(&cd.join("a.dmp"), b"dump", Duration::from_secs(5));
        let cats: Vec<Box<dyn Category>> = vec![Box::new(UserTemp), Box::new(CrashDumps)];
        let sel = vec!["crash-dumps".to_string()];
        let rep = run_clean(&env, &cats, &sel, true, false, &mut |_| true);
        assert_eq!(rep.categories.len(), 1);
        assert_eq!(rep.categories[0].id, "crash-dumps");
        assert!(!cd.join("a.dmp").exists());
        assert!(cd.exists());
    }

    #[test]
    fn crash_dumps_system_roots_need_elevation() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let mini = env.system_root.clone().unwrap().join("Minidump");
        write_aged(&mini.join("m.dmp"), b"m", two_days());
        let p = CrashDumps.plan(&env);
        assert_eq!(p.files, 0);
        assert!(
            p.warnings
                .iter()
                .any(|w| w.contains("requer administrador"))
        );
        let mut e = env.clone();
        e.elevated = true;
        assert_eq!(CrashDumps.plan(&e).files, 1);
        // run_clean's `elevated` argument overrides the env flag.
        let cats: Vec<Box<dyn Category>> = vec![Box::new(CrashDumps)];
        let rep = run_clean(&e, &cats, &[], false, false, &mut |_| true);
        assert_eq!(rep.categories[0].plan.files, 0);
    }

    #[test]
    fn fresh_empty_dir_survives_prune() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let t = env.temp.clone().unwrap();
        fs::create_dir_all(t.join("fresh_empty")).unwrap();
        write_aged(&t.join("x/old.tmp"), b"o", two_days());
        run_clean(&env, &user_temp(), &[], true, false, &mut |_| true);
        assert!(t.join("fresh_empty").exists());
        assert!(!t.join("x").exists());
    }

    #[test]
    fn hardened_roots_and_temp_name() {
        let d = tempfile::tempdir().unwrap();
        let base = env_in(d.path());
        let mut e = base.clone();
        e.temp = e.local_app_data.clone();
        fs::create_dir_all(e.temp.as_ref().unwrap()).unwrap();
        let p = UserTemp.plan(&e);
        assert!(p.warnings.len() == 1 && p.files == 0);
        assert!(!safe_root(e.local_app_data.as_ref().unwrap(), &e));
        let mut e = base.clone();
        e.app_data = Some(d.path().join("roaming"));
        assert!(!safe_root(d.path(), &e));
        assert!(!safe_root(e.app_data.as_ref().unwrap(), &e));
        assert!(!safe_root(e.program_data.as_ref().unwrap(), &e));

        let mut e = base.clone();
        let nt = d.path().join("some/dir/NotTemp");
        write_aged(&nt.join("a.tmp"), b"x", two_days());
        e.temp = Some(nt);
        let p = UserTemp.plan(&e);
        assert_eq!(p.files, 0);
        assert!(!p.warnings.is_empty());

        let mut e = base;
        let ok = d.path().join("some/dir/Temp");
        write_aged(&ok.join("a.tmp"), b"x", two_days());
        e.temp = Some(ok);
        assert_eq!(UserTemp.plan(&e).files, 1);
    }

    #[cfg(unix)]
    #[test]
    fn temp_symlink_to_other_dir_refused() {
        let d = tempfile::tempdir().unwrap();
        let mut e = env_in(d.path());
        let docs = d.path().join("elsewhere/Docs");
        write_aged(&docs.join("a.txt"), b"x", two_days());
        let link = d.path().join("lnk/Temp");
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&docs, &link).unwrap();
        e.temp = Some(link);
        let p = UserTemp.plan(&e);
        assert_eq!(p.files, 0);
        assert!(!p.warnings.is_empty());
        assert!(docs.join("a.txt").exists());
    }

    #[test]
    fn age_rechecked_at_delete_time() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let t = env.temp.clone().unwrap();
        write_aged(&t.join("a.tmp"), b"o", two_days());
        let plan = UserTemp.plan(&env);
        assert_eq!(plan.files, 1);
        // The file is touched after planning.
        write_aged(&t.join("a.tmp"), b"o", Duration::from_secs(1));
        let rep = UserTemp.apply(&env, &plan);
        assert_eq!(rep.deleted, 0);
        assert_eq!(rep.skipped.len(), 1);
        assert!(t.join("a.tmp").exists());
    }

    #[test]
    fn confirm_not_called_when_nothing_planned() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let rep = run_clean(&env, &user_temp(), &[], true, false, &mut |_| {
            panic!("no confirm expected")
        });
        assert!(rep.categories[0].applied.is_none());
    }

    #[test]
    fn declined_marks_cancelled() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        write_aged(&env.temp.clone().unwrap().join("o.tmp"), b"o", two_days());
        let rep = run_clean(&env, &user_temp(), &[], true, false, &mut |_| false);
        assert_eq!(
            rep.categories[0].skipped_reason.as_deref(),
            Some("cancelado pelo usuário")
        );
    }

    #[cfg(windows)]
    #[test]
    fn junction_escape_blocked() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let t = env.temp.clone().unwrap();
        let outside = d.path().join("outside");
        write_aged(&outside.join("secret.txt"), b"s", two_days());
        let link = t.join("jlink");
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&link)
            .arg(&outside)
            .status()
            .unwrap();
        assert!(status.success());
        run_clean(&env, &user_temp(), &[], true, false, &mut |_| true);
        assert!(outside.join("secret.txt").exists());
    }

    #[test]
    fn all_categories_in_spec_order() {
        let ids: Vec<_> = all_categories().iter().map(|c| c.id()).collect();
        assert_eq!(
            ids,
            vec![
                "user-temp",
                "windows-temp",
                "crash-dumps",
                "browser-cache",
                "recycle-bin",
                "windows-update"
            ]
        );
    }
}
