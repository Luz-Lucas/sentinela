use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

#[test]
fn info_prints_version() {
    Command::cargo_bin("sentinela")
        .unwrap()
        .arg("info")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")));
}

use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

fn sentinela(db: &Path) -> Command {
    let mut cmd = Command::cargo_bin("sentinela").unwrap();
    cmd.env("SENTINELA_DB_DIR", db);
    cmd
}

fn json_of(out: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON")
}

const MARKER: &str = "SENTINELA-HARMLESS-MARKER-0f3a9c";

/// DB dir with the marker's hash and a YARA rule matching it (severity malicious).
fn marker_db(base: &Path) -> std::path::PathBuf {
    let db = base.join("db");
    fs::create_dir_all(db.join("rules")).unwrap();
    let hash = hex::encode(Sha256::digest(MARKER.as_bytes()));
    fs::write(db.join("hashes.txt"), format!("{hash}\n")).unwrap();
    fs::write(
        db.join("rules/marker.yar"),
        format!(
            "rule Marker {{ meta: severity = \"malicious\" strings: $a = \"{MARKER}\" condition: $a }}"
        ),
    )
    .unwrap();
    db
}

#[test]
fn scan_marker_via_custom_db_exits_1() {
    let tmp = tempfile::tempdir().unwrap();
    let db = marker_db(tmp.path());
    let dir = tmp.path().join("target");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("marker.bin"), MARKER).unwrap();
    let out = sentinela(&db)
        .args(["scan", "--json"])
        .arg(&dir)
        .assert()
        .code(1)
        .get_output()
        .clone();
    let v = json_of(&out);
    assert_eq!(v["version"], 1);
    assert_eq!(v["summary"]["malicious"], 1);
}

#[cfg(not(windows))]
#[test]
fn scan_eicar_exits_1() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("db");
    let dir = tmp.path().join("target");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("eicar.com"), sentinela::signatures::EICAR).unwrap();
    let out = sentinela(&db)
        .args(["scan", "--json"])
        .arg(&dir)
        .assert()
        .code(1)
        .get_output()
        .clone();
    assert_eq!(json_of(&out)["summary"]["malicious"], 1);
}

#[test]
fn scan_clean_exits_0() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("target");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("a.txt"), "hello").unwrap();
    let out = sentinela(&tmp.path().join("db"))
        .args(["scan", "--json"])
        .arg(&dir)
        .assert()
        .code(0)
        .get_output()
        .clone();
    let v = json_of(&out);
    assert_eq!(v["summary"]["scanned"], 1);
    assert_eq!(v["summary"]["malicious"], 0);
}

#[test]
fn scan_exclude_skips_files() {
    let tmp = tempfile::tempdir().unwrap();
    let db = marker_db(tmp.path());
    let dir = tmp.path().join("target");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("marker.bin"), MARKER).unwrap();
    sentinela(&db)
        .args(["scan", "--exclude", "**/*.bin", "--json"])
        .arg(&dir)
        .assert()
        .code(0);
}

#[test]
fn scan_invalid_exclude_exits_2() {
    let tmp = tempfile::tempdir().unwrap();
    sentinela(&tmp.path().join("db"))
        .args(["scan", "--exclude", "[", "--json"])
        .arg(tmp.path())
        .assert()
        .code(2);
}

#[test]
fn scan_missing_path_exits_2() {
    let tmp = tempfile::tempdir().unwrap();
    sentinela(&tmp.path().join("db"))
        .args(["scan", "--json"])
        .arg(tmp.path().join("nao-existe"))
        .assert()
        .code(2)
        .stderr(contains("nao-existe"));
}

#[test]
fn clean_category_unknown_exits_2() {
    let tmp = tempfile::tempdir().unwrap();
    sentinela(&tmp.path().join("db"))
        .args(["clean", "--category", "foo"])
        .assert()
        .code(2)
        .stderr(contains("user-temp").and(contains("windows-update")));
}

#[test]
fn clean_dry_run_lists_categories() {
    let tmp = tempfile::tempdir().unwrap();
    let out = sentinela(&tmp.path().join("db"))
        .args(["clean", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let v = json_of(&out);
    let ids: Vec<&str> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            "user-temp",
            "windows-temp",
            "crash-dumps",
            "browser-cache",
            "recycle-bin",
            "windows-update"
        ]
    );
    assert!(v["summary"]["files"].is_u64());
    assert!(v["summary"]["bytes"].is_u64());
    assert_eq!(v["summary"]["deleted"], 0);
    assert_eq!(v["summary"]["freed"], 0);
    assert!(v["errors"].is_array());
}

#[test]
fn find_large_json() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("t");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("small"), vec![0u8; 10]).unwrap();
    fs::write(dir.join("big"), vec![0u8; 5000]).unwrap();
    let out = sentinela(&tmp.path().join("db"))
        .args(["find-large", "--top", "1", "--json"])
        .arg(&dir)
        .assert()
        .success()
        .get_output()
        .clone();
    let v = json_of(&out);
    assert_eq!(v["version"], 1);
    assert_eq!(v["items"].as_array().unwrap().len(), 1);
    assert_eq!(v["items"][0]["size"], 5000);
}

#[test]
fn find_dupes_json() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("t");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("a"), "same content").unwrap();
    fs::write(dir.join("b"), "same content").unwrap();
    fs::write(dir.join("c"), "different!!!").unwrap();
    let out = sentinela(&tmp.path().join("db"))
        .args(["find-dupes", "--min-size", "0", "--json"])
        .arg(&dir)
        .assert()
        .success()
        .get_output()
        .clone();
    let v = json_of(&out);
    assert_eq!(v["summary"]["groups"], 1);
    assert_eq!(v["items"][0]["paths"].as_array().unwrap().len(), 2);
}

#[test]
fn info_without_db_says_not_initialized() {
    let tmp = tempfile::tempdir().unwrap();
    sentinela(&tmp.path().join("db"))
        .arg("info")
        .assert()
        .success()
        .stdout(contains("banco não inicializado"));
}

#[test]
fn scan_warns_when_db_not_initialized() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("target");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("a.txt"), "hello").unwrap();
    sentinela(&tmp.path().join("db"))
        .arg("scan")
        .arg(&dir)
        .assert()
        .code(0)
        .stderr(contains("sentinela update"));
}

/// Command with every directory the cleaner reads pointed into `base`.
fn isolated_clean(base: &Path, temp: &Path) -> Command {
    let mut cmd = sentinela(&base.join("db"));
    cmd.env("TEMP", temp)
        .env("TMP", temp)
        .env("TMPDIR", temp)
        .env("LOCALAPPDATA", base.join("local"))
        .env("APPDATA", base.join("roaming"))
        .env("ProgramData", base.join("pdata"))
        .env("SystemRoot", base.join("windows"))
        .env("USERPROFILE", base.join("profile"))
        .env("HOME", base.join("profile"));
    cmd
}

#[test]
fn clean_apply_shows_breakdown_and_cancels_on_eof() {
    let tmp = tempfile::tempdir().unwrap();
    let temp = tmp.path().join("Temp");
    fs::create_dir_all(&temp).unwrap();
    // crash-dumps has no age rule, so a plan exists on every platform.
    let dumps = tmp.path().join("local/CrashDumps");
    fs::create_dir_all(&dumps).unwrap();
    let canary = dumps.join("a.dmp");
    fs::write(&canary, "dump").unwrap();
    isolated_clean(tmp.path(), &temp)
        .args(["clean", "--category", "crash-dumps", "--apply"])
        .write_stdin("")
        .assert()
        .code(0)
        .stderr(contains("crash-dumps: 1 arquivo(s)"))
        .stdout(contains("cancel"));
    assert!(canary.exists());
}

// ---- full / quarantine / restore ------------------------------------------

/// `full` with every location it could touch redirected into `base`.
/// `--root` is the hidden test override: tests must never scan real drives.
fn full_cmd(base: &Path, db: &Path, root: &Path) -> Command {
    let mut cmd = sentinela(db);
    let home = base.join("home");
    fs::create_dir_all(&home).unwrap();
    cmd.env("SENTINELA_QUARANTINE_DIR", base.join("q"))
        .env("HOME", &home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("TEMP", home.join("temp"))
        .env("TMP", home.join("temp"))
        .env("LOCALAPPDATA", home.join("lad"))
        .env("APPDATA", home.join("ad"))
        .env("ProgramData", home.join("pd"))
        .env("SystemRoot", home.join("win"))
        .env("USERPROFILE", home.join("profile"));
    cmd.arg("full").arg("--root").arg(root);
    cmd
}

fn quarantine_cmd(base: &Path, db: &Path) -> Command {
    let mut cmd = sentinela(db);
    cmd.env("SENTINELA_QUARANTINE_DIR", base.join("q"));
    cmd
}

#[test]
fn full_quarantines_hash_hit_reports_yara_only_and_restore_reverses_it() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();
    let db = marker_db(base);
    // A rule that matches a second marker which has no hash entry.
    let yara_marker = "SENTINELA-YARA-ONLY-MARKER-55d1";
    fs::write(
        db.join("rules/only.yar"),
        format!(
            "rule YaraOnly {{ meta: severity = \"malicious\" strings: $a = \"{yara_marker}\" condition: $a }}"
        ),
    )
    .unwrap();
    let root = base.join("drive");
    fs::create_dir(&root).unwrap();
    let bad = root.join("bad.bin");
    let yara_only = root.join("yara.bin");
    fs::write(&bad, MARKER).unwrap();
    fs::write(&yara_only, yara_marker).unwrap();

    let out = full_cmd(base, &db, &root)
        .arg("--json")
        .assert()
        .code(0)
        .get_output()
        .clone();
    let v = json_of(&out);
    assert_eq!(v["version"], 1);
    assert_eq!(v["summary"]["quarantined"], 1);
    assert_eq!(v["summary"]["reported"], 1);
    assert_eq!(v["quarantined"][0]["original_path"], bad.to_str().unwrap());
    assert_eq!(v["reported"][0]["path"], yara_only.to_str().unwrap());
    assert!(!bad.exists());
    assert!(yara_only.exists());

    let list = quarantine_cmd(base, &db)
        .args(["quarantine", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let lv = json_of(&list);
    let id = lv["items"][0]["id"].as_str().unwrap().to_string();

    quarantine_cmd(base, &db)
        .args(["restore", &id])
        .assert()
        .success()
        .stdout(contains("bad.bin"));
    assert_eq!(fs::read(&bad).unwrap(), MARKER.as_bytes());

    // Occupied now: a second restore must fail and exit 2.
    quarantine_cmd(base, &db)
        .args(["restore", &id])
        .assert()
        .code(2);
}

#[test]
fn full_text_output_is_portuguese_and_names_the_reason() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();
    let db = marker_db(base);
    let root = base.join("drive");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("bad.bin"), MARKER).unwrap();
    full_cmd(base, &db, &root)
        .assert()
        .code(0)
        .stdout(
            contains("Quarentena")
                .and(contains("sha256:"))
                .and(contains("bad.bin")),
        )
        .stderr(contains("banco de assinaturas não inicializado"));
}

#[test]
fn quarantine_list_empty_and_restore_unknown_id() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("db");
    quarantine_cmd(tmp.path(), &db)
        .arg("quarantine")
        .assert()
        .success()
        .stdout(contains("vazia"));
    quarantine_cmd(tmp.path(), &db)
        .args(["restore", "nope"])
        .assert()
        .code(2);
}
