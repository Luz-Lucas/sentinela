use std::io::Write;

use serde_json::json;

use crate::scan::ScanReport;
use crate::scan::detector::Severity;

fn label(s: Severity) -> &'static str {
    match s {
        Severity::Malicious => "[MALICIOSO]",
        Severity::Suspicious => "[SUSPEITO]",
        Severity::Info => "[INFO]",
    }
}

pub fn write_scan(report: &ScanReport, json: bool, out: &mut dyn Write) -> std::io::Result<()> {
    let count = |s: Severity| report.items.iter().filter(|i| i.verdict == s).count();
    let malicious = count(Severity::Malicious);
    let suspicious = count(Severity::Suspicious);
    if json {
        let doc = json!({
            "version": 1,
            "summary": {
                "scanned": report.scanned,
                "malicious": malicious,
                "suspicious": suspicious,
                "errors": report.errors.len(),
                "interrupted": report.interrupted,
            },
            "items": report.items,
            "errors": report.errors,
        });
        serde_json::to_writer_pretty(&mut *out, &doc)?;
        writeln!(out)?;
        return Ok(());
    }

    writeln!(
        out,
        "Verificados: {} | Maliciosos: {} | Suspeitos: {} | Erros: {}",
        report.scanned,
        malicious,
        suspicious,
        report.errors.len()
    )?;
    if report.interrupted {
        writeln!(out, "Varredura interrompida antes de terminar.")?;
    }
    for item in &report.items {
        let rules: Vec<&str> = item.findings.iter().map(|f| f.rule.as_str()).collect();
        writeln!(
            out,
            "{} {} — {}",
            label(item.verdict),
            item.path.display(),
            rules.join(", ")
        )?;
    }
    if report.items.is_empty() && !report.interrupted {
        writeln!(out, "Nenhuma ameaça encontrada.")?;
    }
    if !report.errors.is_empty() {
        writeln!(out, "\nNão verificados:")?;
        for e in &report.errors {
            writeln!(out, "  {} — {}", e.path.display(), e.reason)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::detector::{Finding, Severity};
    use crate::scan::{ScanItem, ScanReport};
    use crate::walker::WalkError;
    use std::path::PathBuf;

    fn sample() -> ScanReport {
        ScanReport {
            scanned: 3,
            items: vec![ScanItem {
                path: PathBuf::from("a/evil.bin"),
                verdict: Severity::Malicious,
                findings: vec![Finding {
                    detector: "yara",
                    rule: "Evil".into(),
                    severity: Severity::Malicious,
                    detail: "d".into(),
                }],
            }],
            errors: vec![WalkError {
                path: PathBuf::from("a/locked"),
                reason: "acesso negado".into(),
            }],
            interrupted: false,
        }
    }

    #[test]
    fn report_json_shape() {
        let mut out = Vec::new();
        write_scan(&sample(), true, &mut out).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["version"], 1);
        assert_eq!(v["summary"]["scanned"], 3);
        assert_eq!(v["summary"]["malicious"], 1);
        assert_eq!(v["summary"]["suspicious"], 0);
        assert_eq!(v["summary"]["errors"], 1);
        assert_eq!(v["summary"]["interrupted"], false);
        assert_eq!(v["items"][0]["verdict"], "malicious");
        assert_eq!(v["errors"][0]["reason"], "acesso negado");
    }

    #[test]
    fn report_text_lists_items_and_errors() {
        let mut out = Vec::new();
        write_scan(&sample(), false, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("[MALICIOSO]"));
        assert!(s.contains("Evil"));
        assert!(s.contains("Não verificados"));
        assert!(s.contains("acesso negado"));
    }
}
