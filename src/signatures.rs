//! Local signature database: SHA-256 hash list, YARA rule sources and manifest.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
pub const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
pub const EICAR_RULE: &str = r#"rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file"
        severity = "malicious"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
"#;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SourceInfo {
    pub name: String,
    pub url: String,
    pub fetched_at: String,
    pub count: usize,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Manifest {
    pub sources: Vec<SourceInfo>,
}

pub struct Database {
    pub hashes: HashSet<[u8; 32]>,
    pub rule_sources: Vec<(String, String)>,
    pub manifest: Option<Manifest>,
    pub warnings: Vec<String>,
}

pub fn default_db_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("SENTINELA_DB_DIR")
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Sentinela")
        .join("db")
}

/// Parses one SHA-256 per line (hex, any case). Blank lines and `#` comments are
/// ignored; only the first whitespace-separated token of a line is used.
/// Returns the hash set and the number of invalid lines.
pub fn parse_hashes(text: &str) -> (HashSet<[u8; 32]>, usize) {
    let mut set = HashSet::new();
    let mut invalid = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let token = line.split_whitespace().next().unwrap_or("");
        let mut bytes = [0u8; 32];
        if token.len() == 64 && hex::decode_to_slice(token, &mut bytes).is_ok() {
            set.insert(bytes);
        } else {
            invalid += 1;
        }
    }
    (set, invalid)
}

fn builtin_eicar_hash() -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(EICAR_SHA256, &mut out).expect("EICAR_SHA256 is valid hex");
    out
}

/// Loads the database from `dir`. Never fails: problems become warnings.
/// The EICAR hash and rule are always included.
pub fn load(dir: &Path) -> Database {
    let old = sibling_with_suffix(dir, ".old");
    if !dir.exists() && old.is_dir() {
        let mut db = load_dir(&old);
        db.warnings.push(format!(
            "banco de assinaturas ausente; usando a cópia anterior em {} (rode `sentinela update`)",
            old.display()
        ));
        return db;
    }
    load_dir(dir)
}

fn load_dir(dir: &Path) -> Database {
    let mut db = Database {
        hashes: HashSet::from([builtin_eicar_hash()]),
        rule_sources: vec![("builtin_eicar".to_string(), EICAR_RULE.to_string())],
        manifest: None,
        warnings: Vec::new(),
    };

    let hashes_path = dir.join("hashes.txt");
    if hashes_path.exists() {
        match std::fs::read_to_string(&hashes_path) {
            Ok(text) => {
                let (set, invalid) = parse_hashes(&text);
                db.hashes.extend(set);
                if invalid > 0 {
                    db.warnings
                        .push(format!("hashes.txt: {invalid} invalid line(s) ignored"));
                }
            }
            Err(e) => db.warnings.push(format!("hashes.txt: {e}")),
        }
    }

    let rules_dir = dir.join("rules");
    if let Ok(entries) = std::fs::read_dir(&rules_dir) {
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().is_some_and(|x| x.eq_ignore_ascii_case("yar")))
            .collect();
        paths.sort();
        for path in paths {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            match std::fs::read_to_string(&path) {
                Ok(src) => db.rule_sources.push((name, src)),
                Err(e) => db.warnings.push(format!("rules/{name}: {e}")),
            }
        }
    }

    let manifest_path = dir.join("manifest.json");
    if manifest_path.exists() {
        match std::fs::read_to_string(&manifest_path)
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str::<Manifest>(&t).map_err(|e| e.to_string()))
        {
            Ok(m) => db.manifest = Some(m),
            Err(e) => db.warnings.push(format!("manifest.json: {e}")),
        }
    }

    db
}

fn sibling_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

/// Refuses to touch a directory that exists, is non-empty and does not look
/// like a Sentinela database (guards against a mistaken `SENTINELA_DB_DIR`).
pub fn ensure_replaceable(db_dir: &Path) -> anyhow::Result<()> {
    if !db_dir.exists() {
        return Ok(());
    }
    let non_empty = match std::fs::read_dir(db_dir) {
        Ok(mut it) => it.next().is_some(),
        Err(_) => true, // not a readable directory: be conservative
    };
    let is_db = ["manifest.json", "hashes.txt", "rules"]
        .iter()
        .any(|m| db_dir.join(m).exists());
    if non_empty && !is_db {
        anyhow::bail!(
            "a pasta {} não parece um banco de assinaturas do Sentinela (sem manifest.json, hashes.txt ou rules/); \
             recusando substituí-la. Aponte SENTINELA_DB_DIR para uma pasta vazia ou inexistente.",
            db_dir.display()
        );
    }
    Ok(())
}

/// Replaces `db_dir` with `new_dir` (rename-based). Keeps the old database as
/// `<db_dir>.old` until the swap succeeds, restoring it if the second rename fails.
pub fn swap_in(db_dir: &Path, new_dir: &Path) -> anyhow::Result<()> {
    use anyhow::Context;
    ensure_replaceable(db_dir)?;
    let old_dir = sibling_with_suffix(db_dir, ".old");
    if old_dir.exists() {
        std::fs::remove_dir_all(&old_dir)
            .with_context(|| format!("removing stale {}", old_dir.display()))?;
    }
    let had_old = db_dir.exists();
    if had_old {
        std::fs::rename(db_dir, &old_dir)
            .with_context(|| format!("moving {} aside", db_dir.display()))?;
    }
    if let Err(e) = std::fs::rename(new_dir, db_dir) {
        if had_old {
            let _ = std::fs::rename(&old_dir, db_dir);
        }
        return Err(e).with_context(|| format!("installing {}", new_dir.display()));
    }
    if had_old {
        let _ = std::fs::remove_dir_all(&old_dir);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;

    const H2: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const H3: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn eicar_hash() -> [u8; 32] {
        Sha256::digest(EICAR).into()
    }

    #[test]
    fn eicar_constant_hash_matches() {
        assert_eq!(EICAR.len(), 68);
        assert_eq!(hex::encode(eicar_hash()), EICAR_SHA256);
    }

    #[test]
    fn eicar_rule_compiles_and_matches() {
        let rules = yara_x::compile(EICAR_RULE).expect("rule compiles");
        let mut scanner = yara_x::Scanner::new(&rules);
        let results = scanner.scan(EICAR).expect("scan");
        let names: Vec<_> = results
            .matching_rules()
            .map(|r| r.identifier().to_string())
            .collect();
        assert_eq!(names, vec!["EICAR_Test_File".to_string()]);
        assert!(EICAR_RULE.contains("severity = \"malicious\""));
        let results = scanner.scan(b"harmless").expect("scan");
        assert_eq!(results.matching_rules().count(), 0);
    }

    #[test]
    fn parse_hashes_skips_comments_and_invalid() {
        let text = format!("# c\n{H2}\n\nzzzz\n{}", H3.to_uppercase());
        let (set, invalid) = parse_hashes(&text);
        assert_eq!(set.len(), 2);
        assert_eq!(invalid, 1);
    }

    #[test]
    fn load_missing_dir_has_builtin() {
        let tmp = tempfile::tempdir().unwrap();
        let db = load(&tmp.path().join("nope"));
        assert!(db.hashes.contains(&eicar_hash()));
        assert!(db.rule_sources.iter().any(|(n, _)| n == "builtin_eicar"));
        assert!(db.manifest.is_none());
    }

    #[test]
    fn load_reads_files() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("rules")).unwrap();
        fs::write(tmp.path().join("hashes.txt"), format!("{H2}\n{H3}\n")).unwrap();
        fs::write(tmp.path().join("rules/a.yar"), "rule a { condition: true }").unwrap();
        let db = load(tmp.path());
        assert_eq!(db.hashes.len(), 3);
        assert_eq!(db.rule_sources.len(), 2);
    }

    #[test]
    fn corrupt_manifest_becomes_warning() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("manifest.json"), "{not json").unwrap();
        let db = load(tmp.path());
        assert!(db.manifest.is_none());
        assert_eq!(db.warnings.len(), 1);
    }

    #[test]
    fn valid_manifest_is_loaded() {
        let tmp = tempfile::tempdir().unwrap();
        let m = Manifest {
            sources: vec![SourceInfo {
                name: "x".into(),
                url: "u".into(),
                fetched_at: "t".into(),
                count: 3,
            }],
        };
        fs::write(
            tmp.path().join("manifest.json"),
            serde_json::to_string(&m).unwrap(),
        )
        .unwrap();
        let db = load(tmp.path());
        assert_eq!(db.manifest.unwrap().sources[0].count, 3);
        assert!(db.warnings.is_empty());
    }

    #[test]
    fn swap_in_replaces_and_cleans() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("db");
        let new = tmp.path().join("db.new");
        fs::create_dir_all(&db).unwrap();
        fs::write(db.join("old.txt"), "old").unwrap();
        fs::write(db.join("hashes.txt"), "").unwrap();
        fs::create_dir_all(&new).unwrap();
        fs::write(new.join("new.txt"), "new").unwrap();
        swap_in(&db, &new).unwrap();
        assert!(db.join("new.txt").exists());
        assert!(!db.join("old.txt").exists());
        assert!(!new.exists());
        assert!(!tmp.path().join("db.old").exists());
    }

    #[test]
    fn swap_in_refuses_foreign_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("Docs");
        let new = tmp.path().join("Docs.new");
        fs::create_dir_all(&db).unwrap();
        fs::write(db.join("canary.txt"), "keep").unwrap();
        fs::create_dir_all(&new).unwrap();
        assert!(swap_in(&db, &new).is_err());
        assert!(db.join("canary.txt").exists());
        assert!(new.exists());
    }

    #[test]
    fn swap_in_accepts_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("db");
        let new = tmp.path().join("db.new");
        fs::create_dir_all(&db).unwrap();
        fs::create_dir_all(&new).unwrap();
        fs::write(new.join("n"), "x").unwrap();
        swap_in(&db, &new).unwrap();
        assert!(db.join("n").exists());
    }

    #[test]
    fn load_falls_back_to_old_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let old = tmp.path().join("db.old");
        fs::create_dir_all(&old).unwrap();
        fs::write(old.join("hashes.txt"), format!("{H2}\n")).unwrap();
        let db = load(&tmp.path().join("db"));
        assert_eq!(db.hashes.len(), 2);
        assert!(db.warnings.iter().any(|w| w.contains(".old")));
    }

    #[test]
    fn swap_in_without_existing_db() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("db");
        let new = tmp.path().join("db.new");
        fs::create_dir_all(&new).unwrap();
        fs::write(new.join("new.txt"), "new").unwrap();
        swap_in(&db, &new).unwrap();
        assert!(db.join("new.txt").exists());
        assert!(!new.exists());
    }

    #[test]
    fn default_db_dir_fallback_shape() {
        // Avoid mutating process env (tests run in parallel).
        if std::env::var_os("SENTINELA_DB_DIR").is_none_or(|v| v.is_empty()) {
            assert!(default_db_dir().ends_with("Sentinela/db"));
        }
    }
}
