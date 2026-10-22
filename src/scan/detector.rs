use std::path::Path;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub detector: &'static str,
    pub rule: String,
    pub severity: Severity,
    pub detail: String,
}

/// `bytes` is `None` for files above the size limit.
pub struct FileData<'a> {
    pub path: &'a Path,
    pub bytes: Option<&'a [u8]>,
    pub sha256: [u8; 32],
}

pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    /// `Err` reports that the file could not be inspected (e.g. scan timeout);
    /// it is surfaced as a scan error instead of counting as clean.
    fn inspect(&self, file: &FileData) -> Result<Vec<Finding>, String>;
}
