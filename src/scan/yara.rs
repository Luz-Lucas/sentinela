use crate::scan::detector::{Detector, FileData, Finding, Severity};

/// Upper bound for scanning one file with the whole rule set.
const SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

pub struct CompileOutcome {
    pub rules: Option<yara_x::Rules>,
    /// `(name, error)` for every source that failed to compile.
    pub rejected: Vec<(String, String)>,
}

fn compile_together(sources: &[(&String, &String)]) -> Result<yara_x::Rules, (String, String)> {
    let mut compiler = yara_x::Compiler::new();
    for (name, src) in sources {
        compiler.new_namespace(name);
        if let Err(e) = compiler.add_source(src.as_str()) {
            return Err(((*name).clone(), e.to_string()));
        }
    }
    Ok(compiler.build())
}

/// Compiles `(name, source)` pairs, each in its own namespace. The common case
/// (everything valid) compiles once; only if that fails is each source probed
/// in isolation so a bad one is rejected without discarding the others.
pub fn compile_rules(sources: &[(String, String)]) -> CompileOutcome {
    let all: Vec<(&String, &String)> = sources.iter().map(|(n, s)| (n, s)).collect();
    if !all.is_empty()
        && let Ok(rules) = compile_together(&all)
    {
        return CompileOutcome {
            rules: Some(rules),
            rejected: Vec::new(),
        };
    }
    let mut rejected = Vec::new();
    let mut valid = Vec::new();
    for (name, src) in sources {
        let mut probe = yara_x::Compiler::new();
        match probe.add_source(src.as_str()) {
            Ok(_) => valid.push((name, src)),
            Err(e) => rejected.push((name.clone(), e.to_string())),
        }
    }
    // Valid in isolation but conflicting when combined: reject one at a time.
    while !valid.is_empty() {
        match compile_together(&valid) {
            Ok(rules) => {
                return CompileOutcome {
                    rules: Some(rules),
                    rejected,
                };
            }
            Err((bad, err)) => {
                valid.retain(|(n, _)| **n != bad);
                rejected.push((bad, err));
            }
        }
    }
    CompileOutcome {
        rules: None,
        rejected,
    }
}

pub struct YaraDetector {
    rules: yara_x::Rules,
}

impl YaraDetector {
    pub fn new(rules: yara_x::Rules) -> Self {
        Self { rules }
    }
}

impl Detector for YaraDetector {
    fn name(&self) -> &'static str {
        "yara"
    }

    fn inspect(&self, file: &FileData) -> Result<Vec<Finding>, String> {
        let Some(bytes) = file.bytes else {
            return Ok(Vec::new());
        };
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        let mut scanner = yara_x::Scanner::new(&self.rules);
        scanner.set_timeout(SCAN_TIMEOUT);
        let results = scanner.scan(bytes).map_err(|e| e.to_string())?;
        Ok(results
            .matching_rules()
            .map(|rule| {
                let mut severity = Severity::Suspicious;
                let mut detail = String::new();
                for (key, value) in rule.metadata() {
                    match (key, value) {
                        ("severity", yara_x::MetaValue::String("malicious")) => {
                            severity = Severity::Malicious;
                        }
                        ("description", yara_x::MetaValue::String(d)) => {
                            detail = d.to_string();
                        }
                        _ => {}
                    }
                }
                Finding {
                    detector: "yara",
                    rule: format!("{}:{}", rule.namespace(), rule.identifier()),
                    severity,
                    detail,
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const RULE: &str = r#"rule t { strings: $a = "XYZZY" condition: $a }"#;

    fn detector(src: &str) -> YaraDetector {
        let out = compile_rules(&[("ns".to_string(), src.to_string())]);
        YaraDetector::new(out.rules.unwrap())
    }

    fn file(bytes: Option<&[u8]>) -> FileData<'_> {
        FileData {
            path: Path::new("x"),
            bytes,
            sha256: [0; 32],
        }
    }

    #[test]
    fn detector_is_send_sync() {
        fn assert<T: Send + Sync>() {}
        assert::<YaraDetector>();
    }

    #[test]
    fn matching_rule_reports_finding() {
        let found = detector(RULE).inspect(&file(Some(b"..XYZZY.."))).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::Suspicious);
        assert_eq!(found[0].detector, "yara");
        assert_eq!(found[0].rule, "ns:t");
        assert_eq!(found[0].detail, "");
    }

    #[test]
    fn severity_from_metadata() {
        let src = r#"rule m { meta: severity = "malicious" description = "bad" strings: $a = "XYZZY" condition: $a }"#;
        let found = detector(src).inspect(&file(Some(b"..XYZZY.."))).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::Malicious);
        assert_eq!(found[0].detail, "bad");
    }

    #[test]
    fn bad_source_is_rejected_others_kept() {
        let out = compile_rules(&[
            ("good".to_string(), RULE.to_string()),
            ("bad".to_string(), "rule oops { condition: ".to_string()),
        ]);
        assert_eq!(out.rejected.len(), 1);
        assert_eq!(out.rejected[0].0, "bad");
        let d = YaraDetector::new(out.rules.unwrap());
        assert_eq!(d.inspect(&file(Some(b"..XYZZY.."))).unwrap().len(), 1);
    }

    #[test]
    fn no_bytes_no_findings() {
        assert!(detector(RULE).inspect(&file(None)).unwrap().is_empty());
    }

    #[test]
    fn empty_file_is_clean() {
        assert!(detector(RULE).inspect(&file(Some(&[]))).unwrap().is_empty());
    }
}
