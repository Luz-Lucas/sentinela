use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::scan::detector::{Detector, FileData, Finding, Severity};

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Streaming hash with a 64 KB buffer.
pub fn sha256_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

pub struct HashDetector {
    set: HashSet<[u8; 32]>,
}

impl HashDetector {
    pub fn new(set: HashSet<[u8; 32]>) -> Self {
        Self { set }
    }
}

impl Detector for HashDetector {
    fn name(&self) -> &'static str {
        "hash"
    }
    fn inspect(&self, file: &FileData) -> Vec<Finding> {
        if self.set.contains(&file.sha256) {
            vec![Finding {
                detector: "hash",
                rule: format!("sha256:{}", hex::encode(file.sha256)),
                severity: Severity::Malicious,
                detail: "hash conhecido de malware".to_string(),
            }]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_empty() {
        assert_eq!(
            hex::encode(sha256_bytes(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn file_and_bytes_hash_match() {
        let data: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.bin");
        std::fs::write(&p, &data).unwrap();
        assert_eq!(sha256_file(&p).unwrap(), sha256_bytes(&data));
    }

    #[test]
    fn known_hash_is_malicious() {
        let h = sha256_bytes(b"abc");
        let det = HashDetector::new(HashSet::from([h]));
        let f = FileData {
            path: Path::new("a.exe"),
            bytes: Some(b"abc"),
            sha256: h,
        };
        let out = det.inspect(&f);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Malicious);
        assert_eq!(out[0].detector, "hash");
        assert_eq!(out[0].rule, format!("sha256:{}", hex::encode(h)));
    }

    #[test]
    fn unknown_hash_is_clean() {
        let h = sha256_bytes(b"abc");
        let det = HashDetector::new(HashSet::new());
        let f = FileData {
            path: Path::new("a.exe"),
            bytes: Some(b"abc"),
            sha256: h,
        };
        assert!(det.inspect(&f).is_empty());
    }

    #[test]
    fn works_without_bytes() {
        let h = sha256_bytes(b"abc");
        let det = HashDetector::new(HashSet::from([h]));
        let f = FileData {
            path: Path::new("big.bin"),
            bytes: None,
            sha256: h,
        };
        assert_eq!(det.inspect(&f).len(), 1);
    }
}
