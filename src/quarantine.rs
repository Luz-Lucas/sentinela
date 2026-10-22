//! Restorable quarantine: files are moved (never deleted) into
//! `<dir>/files/<id>` and described by `<dir>/index.json`.

//!
//! Moves are copy -> flush -> re-hash -> remove original, so they also work
//! across volumes, and any failure leaves the original file in place.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::scan::hash::sha256_file;
use crate::walker::is_link_like;

const INDEX: &str = "index.json";
const FILES: &str = "files";

/// `SENTINELA_QUARANTINE_DIR` when set and non-empty, else
/// `<local data dir>/Sentinela/quarantine`.
pub fn default_quarantine_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("SENTINELA_QUARANTINE_DIR")
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Sentinela")
        .join("quarantine")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub rule: String,
    /// RFC 3339, UTC.
    pub quarantined_at: String,
}

fn new_id(path: &Path) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut h = Sha256::new();
    h.update(path.as_os_str().as_encoded_bytes());
    h.update(nanos.to_le_bytes());
    h.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    hex::encode(&h.finalize()[..16])
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric())
}

/// `Ok(None)` when the file is missing, `Err` when unreadable or malformed.
fn read_index(dir: &Path) -> Result<Option<Vec<QuarantineEntry>>> {
    let text = match fs::read_to_string(dir.join(INDEX)) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(Some(serde_json::from_str(&text)?))
}

/// Never panics; a corrupt index lists as empty (and is left untouched).
pub fn list(dir: &Path) -> Vec<QuarantineEntry> {
    read_index(dir).ok().flatten().unwrap_or_default()
}

/// Index for a write. A corrupt one is set aside (never overwritten) so the
/// entries it described can still be recovered by hand.
fn load_for_update(dir: &Path) -> Result<Vec<QuarantineEntry>> {
    match read_index(dir) {
        Ok(v) => Ok(v.unwrap_or_default()),
        Err(_) => {
            let backup = dir.join(format!("{INDEX}.corrupt-{}", new_id(dir)));
            fs::rename(dir.join(INDEX), &backup)
                .context("índice da quarentena corrompido e não foi possível preservá-lo")?;
            Ok(Vec::new())
        }
    }
}

/// Atomic: temp file in the same directory, flushed, then renamed over.
fn write_index(dir: &Path, entries: &[QuarantineEntry]) -> Result<()> {
    let tmp = dir.join(format!("{INDEX}.tmp-{}", new_id(dir)));
    let result = (|| -> Result<()> {
        let mut f = File::create(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(entries)?)?;
        f.sync_all()?;
        fs::rename(&tmp, dir.join(INDEX))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.context("falha ao gravar o índice da quarentena")
}

/// Refuses anything that is not a plain file (symlinks, junctions, dirs).
/// Never follows links.
fn require_plain_file(path: &Path) -> Result<u64> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("não foi possível ler {}", path.display()))?;
    if is_link_like(&meta) || meta.file_type().is_symlink() {
        bail!("recusado: {} é um link/ponto de reanálise", path.display());
    }
    if !meta.is_file() {
        bail!("recusado: {} não é um arquivo comum", path.display());
    }
    Ok(meta.len())
}

/// Copies `src` to a new file `dst` (fails if `dst` exists), flushes it and
/// checks that what landed on disk has the expected SHA-256. On any failure
/// `dst` is removed again. Does not touch `src`.
fn copy_verified(src: &Path, dst: &Path, expected: &[u8; 32]) -> Result<u64> {
    let mut created = false;
    let result = (|| -> Result<u64> {
        let mut input = File::open(src)?;
        let mut out = OpenOptions::new().write(true).create_new(true).open(dst)?;
        created = true;
        let n = io::copy(&mut input, &mut out)?;
        out.sync_all()?;
        drop(out);
        if fs::metadata(dst)?.len() != n {
            bail!("tamanho da cópia diverge");
        }
        if &sha256_file(dst)? != expected {
            bail!("o conteúdo do arquivo não confere com o hash esperado");
        }
        Ok(n)
    })();
    if result.is_err() && created {
        let _ = fs::remove_file(dst);
    }
    result.with_context(|| format!("falha ao copiar {} para {}", src.display(), dst.display()))
}

/// Moves `original` into the quarantine. `sha256` is the hash the caller
/// expects the file to have; if the bytes differ the move is abandoned.
/// The original is only removed after the quarantined copy is verified and
/// indexed; on any failure the original stays where it was.
pub fn quarantine_file(
    dir: &Path,
    original: &Path,
    sha256: [u8; 32],
    rule: &str,
) -> Result<QuarantineEntry> {
    let size = require_plain_file(original)?;
    let files = dir.join(FILES);
    fs::create_dir_all(&files).context("não foi possível criar a pasta de quarentena")?;
    let id = new_id(original);
    let stored = files.join(&id);
    copy_verified(original, &stored, &sha256)?;

    let entry = QuarantineEntry {
        id,
        original_path: original.to_path_buf(),
        sha256: hex::encode(sha256),
        size,
        rule: rule.to_string(),
        quarantined_at: crate::updater::now_rfc3339(),
    };
    let mut entries = match load_for_update(dir) {
        Ok(e) => e,
        Err(e) => {
            let _ = fs::remove_file(&stored);
            return Err(e);
        }
    };
    let before = entries.clone();
    entries.push(entry.clone());
    if let Err(e) = write_index(dir, &entries) {
        let _ = fs::remove_file(&stored);
        return Err(e);
    }
    if let Err(e) = fs::remove_file(original) {
        // Undo: original stays, quarantine holds no phantom entry.
        let _ = write_index(dir, &before);
        let _ = fs::remove_file(&stored);
        return Err(e).with_context(|| {
            format!("não foi possível remover o original {}", original.display())
        });
    }
    Ok(entry)
}

/// Moves a quarantined file back to its original path. Refuses (leaving the
/// quarantined copy alone) when something already exists there.
pub fn restore(dir: &Path, id: &str) -> Result<PathBuf> {
    let mut entries = read_index(dir)
        .map_err(|_| anyhow::anyhow!("índice da quarentena ilegível"))?
        .unwrap_or_default();
    let pos = entries
        .iter()
        .position(|e| e.id == id)
        .with_context(|| format!("id não encontrado na quarentena: {id}"))?;
    let entry = entries[pos].clone();
    if !valid_id(&entry.id) {
        bail!("id inválido no índice: {}", entry.id);
    }
    let stored = dir.join(FILES).join(&entry.id);
    require_plain_file(&stored)?;
    let mut expected = [0u8; 32];
    hex::decode_to_slice(&entry.sha256, &mut expected)
        .context("hash inválido no índice da quarentena")?;
    let target = &entry.original_path;
    // symlink_metadata: a dangling symlink at the target counts as occupied.
    if fs::symlink_metadata(target).is_ok() {
        bail!("o destino já existe: {}", target.display());
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("não foi possível criar {}", parent.display()))?;
    }
    copy_verified(&stored, target, &expected)?;
    entries.remove(pos);
    if let Err(e) = write_index(dir, &entries) {
        let _ = fs::remove_file(target);
        return Err(e);
    }
    // Index no longer references it; a leftover copy is harmless.
    let _ = fs::remove_file(&stored);
    Ok(entry.original_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::hash::{sha256_bytes, sha256_file};
    use std::fs;

    struct Fx {
        _tmp: tempfile::TempDir,
        qdir: PathBuf,
        src_dir: PathBuf,
    }

    // Quarantine dir and file live in different tempdirs: stands in for
    // C: vs D:.
    fn fx() -> Fx {
        let tmp = tempfile::tempdir().unwrap();
        let qdir = tmp.path().join("q");
        let src_dir = tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        Fx {
            _tmp: tmp,
            qdir,
            src_dir,
        }
    }

    #[test]
    fn quarantine_moves_file_and_restore_brings_it_back() {
        let f = fx();
        let p = f.src_dir.join("bad.bin");
        fs::write(&p, b"payload-bytes").unwrap();
        let sha = sha256_bytes(b"payload-bytes");
        let e = quarantine_file(&f.qdir, &p, sha, "sha256:abc").unwrap();
        assert!(!p.exists(), "original must be gone");
        assert_eq!(e.original_path, p);
        assert_eq!(e.size, 13);
        assert_eq!(e.sha256, hex::encode(sha));
        assert_eq!(e.rule, "sha256:abc");
        assert!(e.quarantined_at.ends_with('Z') && e.quarantined_at.len() == 20);
        let stored = f.qdir.join("files").join(&e.id);
        assert_eq!(fs::read(&stored).unwrap(), b"payload-bytes");
        assert_eq!(list(&f.qdir).len(), 1);

        let back = restore(&f.qdir, &e.id).unwrap();
        assert_eq!(back, p);
        assert_eq!(sha256_file(&p).unwrap(), sha);
        assert!(list(&f.qdir).is_empty());
        assert!(!stored.exists());
    }

    #[test]
    fn ids_are_unique_and_filesystem_safe() {
        let f = fx();
        let mut ids = std::collections::HashSet::new();
        for i in 0..20 {
            let p = f.src_dir.join("same.bin");
            fs::write(&p, format!("x{i}")).unwrap();
            let e = quarantine_file(&f.qdir, &p, sha256_bytes(format!("x{i}").as_bytes()), "r")
                .unwrap();
            assert!(e.id.chars().all(|c| c.is_ascii_hexdigit()));
            assert!(ids.insert(e.id));
        }
    }

    #[test]
    fn hash_mismatch_keeps_original() {
        let f = fx();
        let p = f.src_dir.join("a.bin");
        fs::write(&p, b"changed").unwrap();
        let err = quarantine_file(&f.qdir, &p, sha256_bytes(b"other"), "r");
        assert!(err.is_err());
        assert_eq!(fs::read(&p).unwrap(), b"changed");
        assert!(list(&f.qdir).is_empty());
        let files = f.qdir.join("files");
        assert!(!files.exists() || fs::read_dir(files).unwrap().next().is_none());
    }

    #[test]
    fn missing_file_errors() {
        let f = fx();
        let p = f.src_dir.join("nope");
        assert!(quarantine_file(&f.qdir, &p, [0; 32], "r").is_err());
    }

    #[test]
    fn restore_refuses_when_original_occupied() {
        let f = fx();
        let p = f.src_dir.join("bad.bin");
        fs::write(&p, b"evil").unwrap();
        let e = quarantine_file(&f.qdir, &p, sha256_bytes(b"evil"), "r").unwrap();
        fs::write(&p, b"new occupant").unwrap();
        assert!(restore(&f.qdir, &e.id).is_err());
        assert_eq!(fs::read(&p).unwrap(), b"new occupant");
        assert_eq!(fs::read(f.qdir.join("files").join(&e.id)).unwrap(), b"evil");
        assert_eq!(list(&f.qdir).len(), 1);
    }

    #[test]
    fn restore_recreates_parent_dirs_and_unknown_id_errors() {
        let f = fx();
        let sub = f.src_dir.join("a/b");
        fs::create_dir_all(&sub).unwrap();
        let p = sub.join("x.bin");
        fs::write(&p, b"zz").unwrap();
        let e = quarantine_file(&f.qdir, &p, sha256_bytes(b"zz"), "r").unwrap();
        fs::remove_dir_all(f.src_dir.join("a")).unwrap();
        restore(&f.qdir, &e.id).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"zz");
        assert!(restore(&f.qdir, "deadbeef").is_err());
    }

    #[test]
    fn restore_detects_tampered_quarantined_bytes() {
        let f = fx();
        let p = f.src_dir.join("bad.bin");
        fs::write(&p, b"evil").unwrap();
        let e = quarantine_file(&f.qdir, &p, sha256_bytes(b"evil"), "r").unwrap();
        fs::write(f.qdir.join("files").join(&e.id), b"tampered").unwrap();
        assert!(restore(&f.qdir, &e.id).is_err());
        assert!(!p.exists());
        assert_eq!(list(&f.qdir).len(), 1);
    }

    #[test]
    fn corrupt_index_lists_empty_and_loses_nothing() {
        let f = fx();
        let p = f.src_dir.join("one.bin");
        fs::write(&p, b"1").unwrap();
        let e1 = quarantine_file(&f.qdir, &p, sha256_bytes(b"1"), "r").unwrap();
        fs::write(f.qdir.join("index.json"), b"{not json").unwrap();
        assert!(list(&f.qdir).is_empty());
        // Quarantining again must not destroy the corrupt index or stored bytes.
        let q = f.src_dir.join("two.bin");
        fs::write(&q, b"2").unwrap();
        quarantine_file(&f.qdir, &q, sha256_bytes(b"2"), "r").unwrap();
        assert_eq!(list(&f.qdir).len(), 1);
        assert!(f.qdir.join("files").join(&e1.id).exists());
        let backups = fs::read_dir(&f.qdir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|d| {
                d.file_name()
                    .to_string_lossy()
                    .starts_with("index.json.corrupt")
            })
            .count();
        assert_eq!(backups, 1);
    }

    #[test]
    fn list_on_missing_dir_is_empty() {
        let f = fx();
        assert!(list(&f.qdir.join("missing")).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_and_keeps_target() {
        let f = fx();
        let target = f.src_dir.join("target.bin");
        fs::write(&target, b"t").unwrap();
        let link = f.src_dir.join("link.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(quarantine_file(&f.qdir, &link, sha256_bytes(b"t"), "r").is_err());
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(fs::read(&target).unwrap(), b"t");
        assert!(list(&f.qdir).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn restore_does_not_follow_symlink_at_original() {
        let f = fx();
        let p = f.src_dir.join("bad.bin");
        fs::write(&p, b"evil").unwrap();
        let e = quarantine_file(&f.qdir, &p, sha256_bytes(b"evil"), "r").unwrap();
        // Dangling symlink at the original path: exists() would say false.
        std::os::unix::fs::symlink(f.src_dir.join("nowhere"), &p).unwrap();
        assert!(restore(&f.qdir, &e.id).is_err());
        assert!(!f.src_dir.join("nowhere").exists());
        assert_eq!(list(&f.qdir).len(), 1);
    }

    #[test]
    fn default_dir_shape() {
        if std::env::var_os("SENTINELA_QUARANTINE_DIR").is_none_or(|v| v.is_empty()) {
            assert!(default_quarantine_dir().ends_with("Sentinela/quarantine"));
        }
    }
}
