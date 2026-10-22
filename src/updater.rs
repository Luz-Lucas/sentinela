//! Signature updater. Downloads the YARA rule pack and (when an abuse.ch
//! Auth-Key is available; sent in the URL path, as abuse.ch documents) the MalwareBazaar hash export, builds a complete new
//! database in `db.new` and swaps it in atomically.
//!
//! Source verification (2026-10-22):
//! * `RULES_URL` answers 302 to a release asset (~1.7 MB zip) holding a single
//!   `packages/core/yara-rules-core.yar` (~7.9 MB).
//! * The old keyless `bazaar.abuse.ch/export/txt/sha256/recent/` now answers
//!   410 Gone. The export moved to `mb-api.abuse.ch/v2/files/exports/<AUTH-KEY>/`
//!   and requires a free Auth-Key (401 "Invalid auth token" without a valid
//!   one). The exact CSV columns could not be checked without a key, so the
//!   parser accepts both CSV and plain one-hash-per-line.
use anyhow::{Context, bail};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::signatures::{Manifest, SourceInfo, parse_hashes, swap_in};

/// `{KEY}` is replaced by the abuse.ch Auth-Key.
pub const HASHES_URL: &str = "https://mb-api.abuse.ch/v2/files/exports/{KEY}/recent.csv";
pub const RULES_URL: &str =
    "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip";

const HASHES_SOURCE: &str = "malwarebazaar-recent";
const RULES_SOURCE: &str = "yara-forge-core";
const MAX_DOWNLOAD: u64 = 256 * 1024 * 1024;
const MAX_RULE_FILE: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_EXTRACTED: u64 = 256 * 1024 * 1024;
const MAX_ZIP_ENTRIES: usize = 1000;

/// Bounds applied while decompressing the rule pack.
#[derive(Clone, Copy)]
struct ExtractLimits {
    max_entries: usize,
    max_file: u64,
    max_total: u64,
}

const EXTRACT_LIMITS: ExtractLimits = ExtractLimits {
    max_entries: MAX_ZIP_ENTRIES,
    max_file: MAX_RULE_FILE,
    max_total: MAX_TOTAL_EXTRACTED,
};

/// Returned (as the root error) by a [`Fetcher`] when the server answered
/// 401/403, so the updater can skip that source instead of failing.
#[derive(Debug)]
pub struct AuthRequired;

impl std::fmt::Display for AuthRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("autenticação necessária (HTTP 401/403)")
    }
}

impl std::error::Error for AuthRequired {}

pub trait Fetcher {
    fn get(&self, url: &str, headers: &[(&str, String)]) -> anyhow::Result<Vec<u8>>;
}

pub struct HttpFetcher;

impl Fetcher for HttpFetcher {
    fn get(&self, url: &str, headers: &[(&str, String)]) -> anyhow::Result<Vec<u8>> {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(60)))
            .http_status_as_error(false)
            .build()
            .new_agent();
        let mut req = agent.get(url);
        for (k, v) in headers {
            req = req.header(*k, v.as_str());
        }
        // Errors deliberately omit the URL: it may embed the Auth-Key.
        let mut resp = req
            .call()
            .map_err(|e| anyhow::anyhow!("falha de rede: {e}"))?;
        let status = resp.status().as_u16();
        if status == 401 || status == 403 {
            return Err(AuthRequired.into());
        }
        if !(200..300).contains(&status) {
            bail!("o servidor respondeu HTTP {status}");
        }
        resp.body_mut()
            .with_config()
            .limit(MAX_DOWNLOAD)
            .read_to_vec()
            .map_err(|e| anyhow::anyhow!("falha ao ler a resposta: {e}"))
    }
}

#[derive(Debug, Default)]
pub struct UpdateSummary {
    pub hashes: usize,
    /// Rule files (`.yar`) accepted / rejected; the pack may hold many rules per file.
    pub rules_ok: usize,
    pub rules_rejected: usize,
    /// Number of individual rules compiled from the accepted files.
    pub rules_count: usize,
    pub warnings: Vec<String>,
}

fn hashes_url(key: Option<&str>) -> String {
    HASHES_URL.replace("{KEY}", key.unwrap_or(""))
}

/// Normalises the export (CSV or plain text) into one lowercase hash per line.
fn hashes_text(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let found = line
            .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
            .map(|t| t.trim_matches(|c: char| c == '"' || c == '\''))
            .find(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()));
        if let Some(h) = found {
            out.push_str(&h.to_ascii_lowercase());
            out.push('\n');
        }
    }
    out
}

/// UTC timestamp `YYYY-MM-DDTHH:MM:SSZ` from seconds since the Unix epoch.
fn rfc3339_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

pub(crate) fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    rfc3339_utc(secs)
}

/// Extracts every `.yar`/`.yara` file of the zip as `(unique_name, source)`.
/// Aborts if the archive has too many entries or decompresses past the total
/// budget; a single oversized file is skipped with a warning.
fn extract_rules(
    zip_bytes: &[u8],
    warnings: &mut Vec<String>,
    limits: ExtractLimits,
) -> anyhow::Result<Vec<(String, String)>> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes))
        .context("o pacote de regras não é um zip válido")?;
    if archive.len() > limits.max_entries {
        bail!(
            "o pacote de regras tem entradas demais ({} > {}); atualização abortada",
            archive.len(),
            limits.max_entries
        );
    }
    let mut total: u64 = 0;
    let mut sources: Vec<(String, String)> = Vec::new();
    for i in 0..archive.len() {
        let file = archive.by_index(i).context("lendo o pacote de regras")?;
        if file.is_dir() {
            continue;
        }
        let entry = file.name().map(|n| n.into_owned()).unwrap_or_default();
        let path = Path::new(&entry);
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase);
        if !matches!(ext.as_deref(), Some("yar" | "yara")) {
            continue;
        }
        let mut bytes = Vec::new();
        file.take(limits.max_file + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("lendo {entry}"))?;
        total += bytes.len() as u64;
        if total > limits.max_total {
            bail!(
                "o pacote de regras descompacta para mais de {} MiB; atualização abortada",
                limits.max_total / (1024 * 1024)
            );
        }
        if bytes.len() as u64 > limits.max_file {
            warnings.push(format!(
                "Regra ignorada (arquivo grande demais, acima de {} MiB): {entry}",
                limits.max_file / (1024 * 1024)
            ));
            continue;
        }
        let Ok(src) = String::from_utf8(bytes) else {
            warnings.push(format!("Regra ignorada (não é UTF-8): {entry}"));
            continue;
        };
        // Only the sanitised file stem is ever used as an on-disk name.
        let stem: String = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("rules")
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let mut name = stem.clone();
        let mut n = 2;
        while sources.iter().any(|(existing, _)| *existing == name) {
            name = format!("{stem}-{n}");
            n += 1;
        }
        sources.push((name, src));
    }
    Ok(sources)
}

fn truncate(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => format!("{}...", &s[..i]),
        None => s.to_string(),
    }
}

fn read_old_manifest(db_dir: &Path) -> Manifest {
    std::fs::read(db_dir.join("manifest.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Manifest {
            sources: Vec::new(),
        })
}

fn read_old_hashes(db_dir: &Path) -> BTreeSet<[u8; 32]> {
    std::fs::read_to_string(db_dir.join("hashes.txt"))
        .map(|t| parse_hashes(&t).0.into_iter().collect())
        .unwrap_or_default()
}

pub fn update(
    db_dir: &Path,
    fetcher: &dyn Fetcher,
    abuse_ch_key: Option<String>,
) -> anyhow::Result<UpdateSummary> {
    let mut summary = UpdateSummary::default();
    let now = now_rfc3339();

    // 0. Never operate on a folder that is not a Sentinela database.
    crate::signatures::ensure_replaceable(db_dir)?;

    // 1. Download and validate everything before touching the disk.
    let zip_bytes = fetcher
        .get(RULES_URL, &[])
        .context("falha ao baixar as regras YARA")?;
    let sources = extract_rules(&zip_bytes, &mut summary.warnings, EXTRACT_LIMITS)?;
    if sources.is_empty() {
        bail!("o pacote de regras não contém arquivos .yar");
    }
    let outcome = crate::scan::yara::compile_rules(&sources);
    let rejected: BTreeSet<&str> = outcome.rejected.iter().map(|(n, _)| n.as_str()).collect();
    summary.rules_rejected = rejected.len();
    summary.rules_ok = sources.len() - rejected.len();
    for (name, err) in &outcome.rejected {
        summary
            .warnings
            .push(format!("Regra rejeitada ({name}): {err}"));
    }
    if summary.rules_ok == 0 {
        let details: Vec<String> = outcome
            .rejected
            .iter()
            .take(2)
            .map(|(n, e)| format!("{n}: {}", truncate(e, 300)))
            .collect();
        bail!(
            "nenhuma regra do pacote é válida; o banco anterior foi mantido ({})",
            details.join(" | ")
        );
    }
    summary.rules_count = outcome.rules.as_ref().map_or(0, |r| r.iter().count());

    let mut new_hashes: Option<BTreeSet<[u8; 32]>> = None;
    match abuse_ch_key.as_deref().filter(|k| !k.trim().is_empty()) {
        None => summary.warnings.push(
            "Hashes do MalwareBazaar ignorados: defina ABUSE_CH_AUTH_KEY (chave gratuita em auth.abuse.ch)."
                .to_string(),
        ),
        Some(key) => {
            // abuse.ch documents the key as part of the URL path (not a header).
            match fetcher.get(&hashes_url(Some(key)), &[]) {
                Ok(bytes) => {
                    let (set, _) = parse_hashes(&hashes_text(&bytes));
                    if set.is_empty() {
                        summary.warnings.push(
                            "Hashes do MalwareBazaar ignorados: formato de resposta inesperado."
                                .to_string(),
                        );
                    } else {
                        new_hashes = Some(set.into_iter().collect());
                    }
                }
                Err(e) if e.downcast_ref::<AuthRequired>().is_some() => {
                    summary.warnings.push(
                        "Hashes do MalwareBazaar ignorados: chave rejeitada (HTTP 401/403)."
                            .to_string(),
                    );
                }
                Err(e) => {
                    // Keep the previous hashes; never leak the key into messages.
                    let msg = format!("{e:#}").replace(key, "***");
                    summary.warnings.push(format!(
                        "não foi possível baixar os hashes: {}",
                        truncate(&msg, 300)
                    ));
                }
            }
        }
    }

    // 2. Build db.new next to db and swap it in.
    let mut name = db_dir.file_name().unwrap_or_default().to_os_string();
    name.push(".new");
    let new_dir = db_dir.with_file_name(name);
    crate::signatures::ensure_replaceable(&new_dir).context("db.new antigo")?;
    if new_dir.exists() {
        std::fs::remove_dir_all(&new_dir).context("removendo db.new antigo")?;
    }
    let built = build_new_db(
        db_dir,
        &new_dir,
        &sources,
        &rejected,
        new_hashes.as_ref(),
        &now,
        &mut summary,
    )
    .and_then(|()| swap_in(db_dir, &new_dir));
    if let Err(e) = built {
        let _ = std::fs::remove_dir_all(&new_dir);
        return Err(e);
    }
    Ok(summary)
}

fn build_new_db(
    db_dir: &Path,
    new_dir: &Path,
    sources: &[(String, String)],
    rejected: &BTreeSet<&str>,
    new_hashes: Option<&BTreeSet<[u8; 32]>>,
    now: &str,
    summary: &mut UpdateSummary,
) -> anyhow::Result<()> {
    let rules_dir = new_dir.join("rules");
    std::fs::create_dir_all(&rules_dir).context("criando db.new")?;
    for (name, src) in sources {
        if !rejected.contains(name.as_str()) {
            std::fs::write(rules_dir.join(format!("{name}.yar")), src)
                .with_context(|| format!("gravando regra {name}"))?;
        }
    }

    let old_manifest = read_old_manifest(db_dir);
    let mut manifest_sources: Vec<SourceInfo> = old_manifest
        .sources
        .into_iter()
        .filter(|s| s.name != RULES_SOURCE && !(new_hashes.is_some() && s.name == HASHES_SOURCE))
        .collect();

    // Hashes accumulate: new ones are merged into whatever the old db had.
    let mut merged = read_old_hashes(db_dir);
    if let Some(fresh) = new_hashes {
        merged.extend(fresh.iter().copied());
        manifest_sources.push(SourceInfo {
            name: HASHES_SOURCE.to_string(),
            url: HASHES_URL.to_string(),
            fetched_at: now.to_string(),
            count: fresh.len(),
        });
    }
    let mut text = String::from("# Sentinela: SHA-256 de malware conhecido (um por linha)\n");
    for h in &merged {
        text.push_str(&hex::encode(h));
        text.push('\n');
    }
    std::fs::write(new_dir.join("hashes.txt"), text).context("gravando hashes.txt")?;
    summary.hashes = merged.len();

    manifest_sources.push(SourceInfo {
        name: RULES_SOURCE.to_string(),
        url: RULES_URL.to_string(),
        fetched_at: now.to_string(),
        count: summary.rules_count,
    });
    let manifest = Manifest {
        sources: manifest_sources,
    };
    std::fs::write(
        new_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )
    .context("gravando manifest.json")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Write;

    const H1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const H3: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const GOOD: &str = "rule good_one { strings: $a = \"abc\" condition: $a }";
    const BAD: &str = "rule bad_one { condition: undefined_identifier }";

    enum Resp {
        Ok(Vec<u8>),
        Auth,
        Fail,
    }

    struct FakeFetcher(HashMap<String, Resp>);

    impl Fetcher for FakeFetcher {
        fn get(&self, url: &str, _headers: &[(&str, String)]) -> anyhow::Result<Vec<u8>> {
            match self.0.get(url) {
                Some(Resp::Ok(b)) => Ok(b.clone()),
                Some(Resp::Auth) => Err(AuthRequired.into()),
                _ => anyhow::bail!("network down"),
            }
        }
    }

    fn zip_of(files: &[(&str, &str)]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, body) in files {
            w.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(body.as_bytes()).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    /// Both the keyed URL and the keyless one answer with the same response kind.
    fn fake(hashes: Resp, rules: Resp) -> FakeFetcher {
        let mut m = HashMap::new();
        m.insert(hashes_url(Some("k")), hashes);
        m.insert(RULES_URL.to_string(), rules);
        FakeFetcher(m)
    }

    fn two_hashes() -> Resp {
        Resp::Ok(format!("# comment\n{H1}\n{H2}\n").into_bytes())
    }

    #[test]
    fn update_refuses_non_database_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("Docs");
        std::fs::create_dir_all(&db).unwrap();
        std::fs::write(db.join("canary.txt"), "keep").unwrap();
        let f = fake(
            two_hashes(),
            Resp::Ok(zip_of(&[("packages/core/rules.yar", GOOD)])),
        );
        assert!(update(&db, &f, Some("k".into())).is_err());
        assert_eq!(std::fs::read(db.join("canary.txt")).unwrap(), b"keep");
        assert!(!tmp.path().join("Docs.old").exists());
    }

    #[test]
    fn update_refuses_foreign_new_sibling() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("db");
        let foreign_new = tmp.path().join("db.new");
        std::fs::create_dir_all(&foreign_new).unwrap();
        std::fs::write(foreign_new.join("canary.txt"), "keep").unwrap();
        let f = fake(
            two_hashes(),
            Resp::Ok(zip_of(&[("packages/core/rules.yar", GOOD)])),
        );
        assert!(update(&db, &f, Some("k".into())).is_err());
        assert_eq!(
            std::fs::read(foreign_new.join("canary.txt")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn update_writes_db() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("db");
        let f = fake(
            two_hashes(),
            Resp::Ok(zip_of(&[("packages/core/rules.yar", GOOD)])),
        );
        let s = update(&db, &f, Some("k".into())).unwrap();
        assert_eq!(s.hashes, 2);
        assert_eq!(s.rules_ok, 1);
        assert_eq!(s.rules_count, 1);
        assert!(db.join("hashes.txt").is_file());
        assert_eq!(std::fs::read_dir(db.join("rules")).unwrap().count(), 1);
        let m: crate::signatures::Manifest =
            serde_json::from_slice(&std::fs::read(db.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(m.sources.len(), 2);
        assert!(!tmp.path().join("db.new").exists());
        let loaded = crate::signatures::load(&db);
        assert!(loaded.hashes.len() >= 2);
    }

    #[test]
    fn hashes_are_merged_with_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("db");
        std::fs::create_dir_all(&db).unwrap();
        std::fs::write(db.join("hashes.txt"), format!("{H3}\n")).unwrap();
        let f = fake(two_hashes(), Resp::Ok(zip_of(&[("a/rules.yar", GOOD)])));
        let s = update(&db, &f, Some("k".into())).unwrap();
        assert_eq!(s.hashes, 3);
        let text = std::fs::read_to_string(db.join("hashes.txt")).unwrap();
        assert!(text.contains(H3) && text.contains(H1));
    }

    #[test]
    fn network_failure_keeps_old_db() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("db");
        std::fs::create_dir_all(&db).unwrap();
        std::fs::write(db.join("hashes.txt"), format!("{H3}\n")).unwrap();
        let f = fake(Resp::Fail, Resp::Fail);
        assert!(update(&db, &f, Some("k".into())).is_err());
        assert_eq!(
            std::fs::read_to_string(db.join("hashes.txt")).unwrap(),
            format!("{H3}\n")
        );
        assert!(!tmp.path().join("db.new").exists());
    }

    #[test]
    fn invalid_rules_rejected_individually() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("db");
        let f = fake(
            two_hashes(),
            Resp::Ok(zip_of(&[("good.yar", GOOD), ("bad.yar", BAD)])),
        );
        let s = update(&db, &f, Some("k".into())).unwrap();
        assert_eq!(s.rules_ok, 1);
        assert_eq!(s.rules_rejected, 1);
        assert_eq!(std::fs::read_dir(db.join("rules")).unwrap().count(), 1);
    }

    #[test]
    fn missing_key_skips_hashes_with_warning() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("db");
        let f = fake(Resp::Auth, Resp::Ok(zip_of(&[("r.yar", GOOD)])));
        let s = update(&db, &f, None).unwrap();
        assert!(!s.warnings.is_empty());
        assert_eq!(s.rules_ok, 1);
        assert_eq!(s.hashes, 0);
    }

    #[test]
    fn rejected_key_skips_hashes_with_warning() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("db");
        let f = fake(Resp::Auth, Resp::Ok(zip_of(&[("r.yar", GOOD)])));
        let s = update(&db, &f, Some("k".into())).unwrap();
        assert!(!s.warnings.is_empty());
        assert_eq!(s.rules_ok, 1);
    }

    #[test]
    fn non_auth_hash_failure_degrades_to_warning() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("db");
        std::fs::create_dir_all(&db).unwrap();
        std::fs::write(db.join("hashes.txt"), format!("{H3}\n")).unwrap();
        let f = fake(Resp::Fail, Resp::Ok(zip_of(&[("r.yar", GOOD)])));
        let s = update(&db, &f, Some("k".into())).unwrap();
        assert_eq!(s.rules_ok, 1);
        assert_eq!(s.hashes, 1);
        assert!(s.warnings.iter().any(|w| w.contains("baixar os hashes")));
        assert!(
            std::fs::read_to_string(db.join("hashes.txt"))
                .unwrap()
                .contains(H3)
        );
        assert_eq!(std::fs::read_dir(db.join("rules")).unwrap().count(), 1);
    }

    #[test]
    fn key_never_leaks() {
        struct Leaky;
        impl Fetcher for Leaky {
            fn get(&self, url: &str, _h: &[(&str, String)]) -> anyhow::Result<Vec<u8>> {
                if url == RULES_URL {
                    Ok(zip_of(&[("r.yar", GOOD)]))
                } else {
                    anyhow::bail!("falha em {url}")
                }
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("db");
        let s = update(&db, &Leaky, Some("SEKRET-KEY-123".into())).unwrap();
        assert!(s.warnings.iter().all(|w| !w.contains("SEKRET-KEY-123")));
        let manifest = std::fs::read_to_string(db.join("manifest.json")).unwrap();
        assert!(!manifest.contains("SEKRET-KEY-123"));
    }

    #[test]
    fn all_rejected_error_includes_reason() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("db");
        let f = fake(two_hashes(), Resp::Ok(zip_of(&[("bad.yar", BAD)])));
        let e = update(&db, &f, Some("k".into())).unwrap_err();
        assert!(format!("{e:#}").contains("bad"), "{e:#}");
        assert!(format!("{e:#}").contains("undefined_identifier"), "{e:#}");
    }

    #[test]
    fn extraction_is_bounded() {
        let lim = ExtractLimits {
            max_entries: 2,
            max_file: 100,
            max_total: 150,
        };
        let mut w = Vec::new();
        // too many entries
        let z = zip_of(&[("a.yar", GOOD), ("b.yar", GOOD), ("c.yar", GOOD)]);
        assert!(extract_rules(&z, &mut w, lim).is_err());
        // total budget exceeded (2 x 90 bytes)
        let big = "a".repeat(90);
        let z = zip_of(&[("a.yar", &big), ("b.yar", &big)]);
        assert!(extract_rules(&z, &mut w, lim).is_err());
        // oversized single file is skipped with a warning, not truncated
        let huge = "a".repeat(101);
        let z = zip_of(&[("a.yar", &huge), ("b.yar", GOOD)]);
        let roomy = ExtractLimits {
            max_total: 1000,
            ..lim
        };
        let got = extract_rules(&z, &mut w, roomy).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "b");
        assert!(w.iter().any(|m| m.contains("grande demais")));
    }

    #[test]
    fn csv_export_lines_are_understood() {
        let csv = format!(
            "# header\n\"first_seen\",\"sha256_hash\",\"md5\"\n\"2026-01-01\", \"{H1}\", \"x\"\n{H2}\n"
        );
        let (set, _) = crate::signatures::parse_hashes(&hashes_text(csv.as_bytes()));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn timestamp_is_rfc3339() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_782_864_000), "2026-07-01T00:00:00Z");
    }
}
