//! Heuristic PE analysis. Never produces `Malicious`: only `Suspicious`.

use goblin::pe::PE;
use goblin::pe::section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};

use crate::scan::detector::{Detector, FileData, Finding, Severity};

pub const SUSPICIOUS_THRESHOLD: u32 = 4;

const HIGH_ENTROPY: f64 = 7.2;
const PACKER_SECTIONS: &[&str] = &[
    "UPX0", "UPX1", ".aspack", ".adata", ".petite", ".MPRESS1", ".MPRESS2", ".themida", ".vmp0",
    ".vmp1",
];

/// Shannon entropy in bits per byte (0.0 for empty input).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[derive(Debug, Clone)]
pub struct PeReport {
    pub score: u32,
    pub signals: Vec<String>,
}

/// Returns `None` when `bytes` is not a parseable PE.
pub fn analyze(bytes: &[u8]) -> Option<PeReport> {
    let pe = PE::parse(bytes).ok()?;
    let mut score = 0u32;
    let mut signals = Vec::new();
    let mut packer_hit = false;

    for s in &pe.sections {
        let name = s.name().unwrap_or("").trim_end_matches('\0').to_string();

        // Attacker-controlled offsets: saturate and clamp to the file.
        let start = s.pointer_to_raw_data as usize;
        let end = start
            .saturating_add(s.size_of_raw_data as usize)
            .min(bytes.len());
        if start < end {
            let e = shannon_entropy(&bytes[start..end]);
            if e > HIGH_ENTROPY {
                score += 2;
                signals.push(format!("high-entropy section {name} ({e:.2})"));
            }
        }

        let c = s.characteristics;
        if c & IMAGE_SCN_MEM_WRITE != 0 && c & IMAGE_SCN_MEM_EXECUTE != 0 {
            score += 2;
            signals.push(format!("writable+executable section {name}"));
        }

        if !packer_hit && PACKER_SECTIONS.contains(&name.as_str()) {
            packer_hit = true;
            score += 2;
            signals.push(format!("packer section name {name}"));
        }
    }

    if pe.entry != 0 {
        let entry = pe.entry as u64;
        let in_exec = pe.sections.iter().any(|s| {
            let size = s.virtual_size.max(s.size_of_raw_data) as u64;
            let va = s.virtual_address as u64;
            entry >= va && entry < va + size && s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
        });
        if !in_exec {
            score += 1;
            signals.push("entry point outside executable section".to_string());
        }
    }

    let signed = pe
        .header
        .optional_header
        .and_then(|oh| oh.data_directories.get_certificate_table().copied())
        .is_some_and(|d| d.size != 0);
    if !signed {
        score += 1;
        signals.push("no Authenticode signature".to_string());
    }

    Some(PeReport { score, signals })
}

#[derive(Default)]
pub struct PeDetector;

impl Detector for PeDetector {
    fn name(&self) -> &'static str {
        "pe"
    }

    fn inspect(&self, file: &FileData) -> Vec<Finding> {
        let Some(bytes) = file.bytes else {
            return Vec::new();
        };
        match analyze(bytes) {
            Some(r) if r.score >= SUSPICIOUS_THRESHOLD => vec![Finding {
                detector: "pe",
                rule: "pe-heuristics".to_string(),
                severity: Severity::Suspicious,
                detail: r.signals.join("; "),
            }],
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const TEXT: u32 = 0x6000_0020;
    const WX: u32 = 0xE000_0020;

    fn le16(v: &mut Vec<u8>, x: u16) {
        v.extend_from_slice(&x.to_le_bytes());
    }
    fn le32(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_le_bytes());
    }

    /// Minimal PE32+ with the given sections `(name, characteristics, raw data)`.
    fn build_pe(sections: &[(&str, u32, Vec<u8>)], entry_rva: u32, signed: bool) -> Vec<u8> {
        let n = sections.len();
        let headers_end = 0x40 + 4 + 20 + 240 + 40 * n;
        let first_raw = headers_end.div_ceil(0x200) * 0x200;
        let cert_off: usize = first_raw
            + sections
                .iter()
                .map(|(_, _, d)| d.len().div_ceil(0x200) * 0x200)
                .sum::<usize>();

        let mut v = vec![0u8; 0x40];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        v.extend_from_slice(b"PE\0\0");
        // COFF
        le16(&mut v, 0x8664);
        le16(&mut v, n as u16);
        le32(&mut v, 0);
        le32(&mut v, 0);
        le32(&mut v, 0);
        le16(&mut v, 240);
        le16(&mut v, 0x22);
        // Optional header (PE32+)
        le16(&mut v, 0x20b);
        v.extend_from_slice(&[14, 0]);
        le32(&mut v, 0);
        le32(&mut v, 0);
        le32(&mut v, 0);
        le32(&mut v, entry_rva);
        le32(&mut v, 0x1000);
        v.extend_from_slice(&0x1_4000_0000u64.to_le_bytes());
        le32(&mut v, 0x1000);
        le32(&mut v, 0x200);
        for _ in 0..6 {
            le16(&mut v, 6);
        }
        le32(&mut v, 0);
        le32(&mut v, 0x1000 * (n as u32 + 1));
        le32(&mut v, first_raw as u32);
        le32(&mut v, 0);
        le16(&mut v, 3);
        le16(&mut v, 0);
        for _ in 0..4 {
            v.extend_from_slice(&0x10000u64.to_le_bytes());
        }
        le32(&mut v, 0);
        le32(&mut v, 16);
        for i in 0..16 {
            if i == 4 && signed {
                le32(&mut v, cert_off as u32);
                le32(&mut v, 16);
            } else {
                le32(&mut v, 0);
                le32(&mut v, 0);
            }
        }
        // Section table
        let mut raw = first_raw;
        for (i, (name, ch, data)) in sections.iter().enumerate() {
            let mut nm = [0u8; 8];
            nm[..name.len()].copy_from_slice(name.as_bytes());
            v.extend_from_slice(&nm);
            le32(&mut v, data.len() as u32);
            le32(&mut v, 0x1000 * (i as u32 + 1));
            let padded = data.len().div_ceil(0x200) * 0x200;
            le32(&mut v, padded as u32);
            le32(&mut v, raw as u32);
            le32(&mut v, 0);
            le32(&mut v, 0);
            le16(&mut v, 0);
            le16(&mut v, 0);
            le32(&mut v, *ch);
            raw += padded;
        }
        v.resize(first_raw, 0);
        for (_, _, data) in sections {
            v.extend_from_slice(data);
            let padded = data.len().div_ceil(0x200) * 0x200;
            v.resize(v.len() + padded - data.len(), 0);
        }
        if signed {
            // WIN_CERTIFICATE: length, revision 2.0, PKCS#7 type, dummy payload.
            le32(&mut v, 16);
            le16(&mut v, 0x0200);
            le16(&mut v, 2);
            v.extend_from_slice(&[0xAA; 8]);
        }
        v
    }

    fn noise(len: usize) -> Vec<u8> {
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    fn inspect(bytes: &[u8]) -> Vec<Finding> {
        PeDetector.inspect(&FileData {
            path: Path::new("x.exe"),
            bytes: Some(bytes),
            sha256: [0; 32],
        })
    }

    #[test]
    fn builder_produces_parseable_pe() {
        let b = build_pe(&[(".text", TEXT, vec![0x90; 600])], 0x1000, true);
        let pe = goblin::pe::PE::parse(&b).expect("parse");
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.entry, 0x1000);
        let dd = pe.header.optional_header.unwrap().data_directories;
        assert_eq!(dd.get_certificate_table().unwrap().size, 16);
        let b = build_pe(&[(".text", TEXT, vec![0x90; 600])], 0x1000, false);
        let pe = goblin::pe::PE::parse(&b).unwrap();
        let dd = pe.header.optional_header.unwrap().data_directories;
        assert_eq!(dd.get_certificate_table().map_or(0, |d| d.size), 0);
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[7u8; 4096]), 0.0);
        let all: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!((shannon_entropy(&all) - 8.0).abs() < 0.01);
    }

    #[test]
    fn not_pe_returns_none() {
        assert!(analyze(b"just some plain text, definitely not a PE").is_none());
    }

    #[test]
    fn truncated_mz_is_none() {
        let mut b = b"MZ".to_vec();
        b.extend(noise(100));
        assert!(analyze(&b).is_none());
        assert!(inspect(&b).is_empty());
    }

    #[test]
    fn truncated_valid_pe_never_panics() {
        let b = build_pe(&[("UPX1", WX, noise(4096))], 0x9000, false);
        for len in 0..b.len() {
            let _ = analyze(&b[..len]);
        }
    }

    #[test]
    fn normal_signed_pe_is_clean() {
        let b = build_pe(&[(".text", TEXT, vec![0x90; 2048])], 0x1000, true);
        let r = analyze(&b).unwrap();
        assert_eq!(r.score, 0, "{:?}", r.signals);
        assert!(inspect(&b).is_empty());
    }

    #[test]
    fn packed_pe_is_suspicious() {
        let b = build_pe(&[("UPX1", WX, noise(4096))], 0x1000, false);
        let f = inspect(&b);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Suspicious);
        assert_eq!(f[0].detector, "pe");
        assert_eq!(f[0].rule, "pe-heuristics");
        assert!(f[0].detail.contains("UPX"));
    }

    #[test]
    fn never_malicious() {
        let b = build_pe(
            &[
                ("UPX0", WX, noise(4096)),
                (".vmp0", WX, noise(4096)),
                (".themida", WX, noise(4096)),
            ],
            0xF0000,
            false,
        );
        let f = inspect(&b);
        assert!(!f.is_empty());
        assert!(f.iter().all(|x| x.severity != Severity::Malicious));
    }

    #[test]
    fn no_bytes_no_findings() {
        let f = PeDetector.inspect(&FileData {
            path: Path::new("x.exe"),
            bytes: None,
            sha256: [0; 32],
        });
        assert!(f.is_empty());
    }
}
