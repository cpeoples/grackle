//! Output formats.
//!
//! One [`Format`] enum, one `render` entrypoint, and a small function per
//! format. Every formatter reads the same [`FileResult`] slice and the
//! per-finding [`Finding`] (severity, location, compliance metadata, the
//! offending snippet, and the generated remediation), so adding a format never
//! touches the scanner.

use crate::rules::{Finding, Severity};
use crate::scanner::FileResult;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// A machine- or human-readable output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
    Markdown,
    Sarif,
    GitlabSast,
    Junit,
    Csv,
    Xml,
    Yaml,
    Html,
    CycloneDx,
}

impl Format {
    /// Parse a `--format` value.
    pub fn parse(s: &str) -> Result<Self, String> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "text" | "txt" => Format::Text,
            "json" => Format::Json,
            "markdown" | "md" => Format::Markdown,
            "sarif" => Format::Sarif,
            "gitlab" | "gitlab-sast" | "gl-sast" => Format::GitlabSast,
            "junit" | "junit-xml" => Format::Junit,
            "csv" => Format::Csv,
            "xml" => Format::Xml,
            "yaml" | "yml" => Format::Yaml,
            "html" => Format::Html,
            "cyclonedx" | "cyclonedx-json" | "cdx" => Format::CycloneDx,
            other => return Err(format!("unknown format '{other}'")),
        })
    }

    /// Infer a format from an output file extension (`report.sarif` -> Sarif).
    /// `.json` is ambiguous, so callers pass an explicit format for SARIF /
    /// GitLab; here it maps to the plain JSON report.
    pub fn from_path(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        Some(match ext.as_str() {
            "txt" | "text" => Format::Text,
            "json" => Format::Json,
            "md" | "markdown" => Format::Markdown,
            "sarif" => Format::Sarif,
            "junit" => Format::Junit,
            "csv" => Format::Csv,
            "xml" => Format::Xml,
            "yaml" | "yml" => Format::Yaml,
            "html" | "htm" => Format::Html,
            _ => return None,
        })
    }
}

/// Render `results` in `format`. The `total` is precomputed so formatters that
/// print a summary line stay consistent with the caller's count.
pub fn render(results: &[FileResult], total: usize, format: Format) -> String {
    match format {
        Format::Text => text(results, total),
        Format::Json => json(results),
        Format::Markdown => markdown(results, total),
        Format::Sarif => sarif(results),
        Format::GitlabSast => gitlab_sast(results),
        Format::Junit => junit(results, total),
        Format::Csv => csv(results),
        Format::Xml => xml(results),
        Format::Yaml => yaml(results),
        Format::Html => html(results, total),
        Format::CycloneDx => cyclonedx(results),
    }
}

/// Flatten `(path, finding)` pairs in file, then finding order.
fn flat(results: &[FileResult]) -> impl Iterator<Item = (&str, &Finding)> {
    results.iter().flat_map(|r| {
        r.findings
            .iter()
            .map(move |f| (r.path.to_str().unwrap_or(""), f))
    })
}

fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
    }
}

fn security_severity(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
    }
}

/// XML-escape text for the SARIF-free XML / JUnit / HTML formatters.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// CSV-escape one field per RFC 4180 (quote when it holds a comma, quote, or
/// newline; double embedded quotes).
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn text(results: &[FileResult], total: usize) -> String {
    if results.is_empty() {
        return "No fork-triggerable agent findings.\n".to_string();
    }
    let mut out = String::new();
    for (path, f) in flat(results) {
        let m = &f.metadata;
        let also = if f.locations.len() > 1 {
            let extra: Vec<String> = f
                .locations
                .iter()
                .filter(|&&l| l != f.line_number)
                .map(|l| l.to_string())
                .collect();
            format!("\n  Also invoked at line(s): {}", extra.join(", "))
        } else {
            String::new()
        };
        out.push_str(&format!(
            "{}:{} [{}] ({} confidence) {}\n  {}\n  {}{}\n  CWE: {} | OWASP: {} | OWASP-LLM: {} | MITRE ATT&CK: {} | MITRE ATLAS: {}\n{}\n",
            path,
            f.line_number,
            f.severity.as_str(),
            f.confidence.as_str(),
            f.rule_id,
            f.title,
            f.recommendation,
            also,
            m.cwe.join(", "),
            m.owasp_appsec.join(", "),
            m.owasp_llm.join(", "),
            m.mitre_attack.join(", "),
            m.mitre_atlas.join(", "),
            f.remediation,
        ));
    }
    out.push_str(&format!("\n{total} finding(s).\n"));
    out
}

fn json(results: &[FileResult]) -> String {
    let items: Vec<serde_json::Value> = flat(results)
        .map(|(path, f)| {
            let m = &f.metadata;
            serde_json::json!({
                "path": path,
                "line": f.line_number,
                "locations": f.locations,
                "severity": f.severity.as_str(),
                "confidence": f.confidence.as_str(),
                "confidence_score": f.confidence.score(),
                "rule_id": f.rule_id,
                "title": f.title,
                "recommendation": f.recommendation,
                "code_snippet": f.code_snippet,
                "remediation": f.remediation,
                "cwe": m.cwe,
                "owasp_appsec": m.owasp_appsec,
                "owasp_llm": m.owasp_llm,
                "owasp_asvs": m.owasp_asvs,
                "mitre_attack": m.mitre_attack,
                "mitre_atlas": m.mitre_atlas,
                "cis_controls": m.cis_controls,
                "nist_controls": m.nist_controls,
                "pci_dss": m.pci_dss,
                "soc2": m.soc2,
            })
        })
        .collect();
    serde_json::to_string_pretty(&items).unwrap()
}

fn markdown(results: &[FileResult], total: usize) -> String {
    let mut out = String::from("# grackle findings\n\n");
    if results.is_empty() {
        out.push_str("No fork-triggerable agent findings.\n");
        return out;
    }
    out.push_str(&format!("**{total} finding(s).**\n"));
    for (path, f) in flat(results) {
        let m = &f.metadata;
        out.push_str(&format!(
            "\n## {} `{}`\n\n- **File:** `{}:{}`\n- **Severity:** {}\n- **Confidence:** {}\n- **CWE:** {}\n- **OWASP:** {}\n- **MITRE ATT&CK:** {}\n\n{}\n",
            f.title,
            f.rule_id,
            path,
            f.line_number,
            f.severity.as_str(),
            f.confidence.as_str(),
            m.cwe.join(", "),
            m.owasp_appsec.join(", "),
            m.mitre_attack.join(", "),
            f.remediation,
        ));
    }
    out
}

/// Namespaced compliance tags for a finding, mirroring the SARIF formatter's
/// `_tags_for` (CWE-/OWASP-/T#### etc), so tag filtering works the same way.
fn tags_for(f: &Finding) -> Vec<String> {
    let m = &f.metadata;
    let mut tags = vec!["security".to_string()];
    tags.extend(m.cwe.iter().map(|s| s.to_string()));
    tags.extend(m.owasp_appsec.iter().map(|s| format!("OWASP-{s}")));
    tags.extend(m.owasp_llm.iter().map(|s| format!("OWASP-{s}")));
    tags.extend(m.owasp_asvs.iter().map(|s| format!("OWASP-ASVS-{s}")));
    tags.extend(m.mitre_attack.iter().map(|s| s.to_string()));
    tags.extend(m.mitre_atlas.iter().map(|s| s.to_string()));
    tags.extend(m.cis_controls.iter().map(|s| s.to_string()));
    tags.extend(m.nist_controls.iter().map(|s| format!("NIST-{s}")));
    tags.extend(m.pci_dss.iter().map(|s| format!("PCI-DSS-{s}")));
    tags.extend(m.soc2.iter().map(|s| format!("SOC2-{s}")));
    let mut seen = HashSet::new();
    tags.retain(|t| seen.insert(t.clone()));
    tags
}

/// Serialize the full built-in rule catalog (id, severity, title, family,
/// agent, recommendation, and every compliance framework) as pretty JSON. This
/// is the source the documentation generator consumes so the published rule
/// pages always match the shipped rules.
pub fn rules_json(rules: &[crate::rules::RuleSpec]) -> String {
    let items: Vec<serde_json::Value> = rules
        .iter()
        .map(|r| {
            let m = &r.metadata;
            serde_json::json!({
                "id": r.id,
                "severity": r.severity.as_str(),
                "title": r.title,
                "concern": concern_of(&r.family),
                "agent": agent_of(r.id),
                "recommendation": r.recommendation,
                "compliance": {
                    "cwe": m.cwe,
                    "owasp_appsec": m.owasp_appsec,
                    "owasp_llm": m.owasp_llm,
                    "owasp_asvs": m.owasp_asvs,
                    "mitre_attack": m.mitre_attack,
                    "mitre_atlas": m.mitre_atlas,
                    "cis_controls": m.cis_controls,
                    "nist_controls": m.nist_controls,
                    "pci_dss": m.pci_dss,
                    "soc2": m.soc2,
                },
                "positive_example": r.positive_examples.first().copied().unwrap_or(""),
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "tool": "grackle",
        "version": env!("CARGO_PKG_VERSION"),
        "rules": items,
    }))
    .unwrap()
}

/// The post-filter family a rule belongs to, as a stable label for the docs.
fn concern_of(family: &crate::rules::Family) -> &'static str {
    match family {
        crate::rules::Family::Installed { .. } => "installed",
        crate::rules::Family::Action => "action",
        crate::rules::Family::Gitlab { .. } => "gitlab",
        crate::rules::Family::ForkShellExec { .. } => "shell-exec",
    }
}

/// A human agent name derived from the rule id. Rule ids follow
/// `fork_triggerable_<agent>_agent_with_...` / `..._with_write_or_exec_...`, so
/// the middle segment names the family the docs group by.
fn agent_of(id: &str) -> String {
    let mut s = id.trim_start_matches("fork_triggerable_");
    s = s.trim_start_matches("fork_reachable_");
    for suffix in [
        "_agent_with_repo_write",
        "_agent_with_write_or_exec_tools",
        "_agent_with_write_or_exec",
        "_agent_with_repo_mutating_gh_tools",
        "_agent_with_write_or_exec_sandbox",
        "_ci_agent_with_write_or_exec",
    ] {
        if let Some(stripped) = s.strip_suffix(suffix) {
            s = stripped;
            break;
        }
    }
    s.replace('_', " ")
}

fn sarif(results: &[FileResult]) -> String {
    let mut rule_catalog: Vec<serde_json::Value> = Vec::new();
    let mut rule_index: HashMap<&str, usize> = HashMap::new();
    for (_, f) in flat(results) {
        if rule_index.contains_key(f.rule_id) {
            continue;
        }
        rule_index.insert(f.rule_id, rule_catalog.len());
        rule_catalog.push(serde_json::json!({
            "id": f.rule_id,
            "name": f.rule_id,
            "shortDescription": { "text": f.title },
            "fullDescription": { "text": f.title },
            "help": { "text": f.recommendation, "markdown": f.remediation },
            "defaultConfiguration": { "level": sarif_level(f.severity) },
            "properties": {
                "precision": "high",
                "tags": tags_for(f),
                "security-severity": security_severity(f.severity),
                "severity": f.severity.as_str(),
            },
        }));
    }

    let sarif_results: Vec<serde_json::Value> = flat(results)
        .map(|(path, f)| {
            serde_json::json!({
                "ruleId": f.rule_id,
                "ruleIndex": rule_index.get(f.rule_id).copied().unwrap_or(0),
                "level": sarif_level(f.severity),
                "message": { "text": f.title },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": path },
                        "region": { "startLine": f.line_number, "endLine": f.line_number },
                    }
                }],
                "properties": {
                    "recommendation": f.recommendation,
                    "codeSnippet": f.code_snippet,
                    "remediationExample": f.remediation,
                    "tags": tags_for(f),
                    "security-severity": security_severity(f.severity),
                    "severity": f.severity.as_str(),
                    "confidence": f.confidence.as_str(),
                    "confidence-score": f.confidence.score(),
                },
                "fixes": [{
                    "description": { "text": "Gate the agent job and remove write/exec access" },
                    "artifactChanges": [{
                        "artifactLocation": { "uri": path },
                        "replacements": [{
                            "deletedRegion": { "startLine": f.line_number, "endLine": f.line_number },
                            "insertedContent": { "text": f.remediation },
                        }],
                    }],
                }],
            })
        })
        .collect();

    let doc = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "grackle",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/cpeoples/grackle",
                "rules": rule_catalog,
            }},
            "results": sarif_results,
        }],
    });
    serde_json::to_string_pretty(&doc).unwrap()
}

fn gitlab_sast(results: &[FileResult]) -> String {
    let vulns: Vec<serde_json::Value> = flat(results)
        .map(|(path, f)| {
            let m = &f.metadata;
            let mut identifiers = vec![serde_json::json!({
                "type": "grackle_rule_id",
                "name": format!("grackle rule: {}", f.rule_id),
                "value": f.rule_id,
                "url": "https://github.com/cpeoples/grackle",
            })];
            for cwe in m.cwe {
                let numeric = cwe.strip_prefix("CWE-").unwrap_or(cwe);
                identifiers.push(serde_json::json!({
                    "type": "cwe",
                    "name": cwe,
                    "value": numeric,
                    "url": format!("https://cwe.mitre.org/data/definitions/{numeric}.html"),
                }));
            }
            for t in m.mitre_attack {
                identifiers.push(serde_json::json!({
                    "type": "mitre_attack",
                    "name": format!("MITRE ATT&CK {t}"),
                    "value": t,
                    "url": format!("https://attack.mitre.org/techniques/{}/", t.replace('.', "/")),
                }));
            }
            let severity = match f.severity {
                Severity::Critical => "Critical",
                Severity::High => "High",
            };
            let confidence = match f.confidence {
                crate::rules::Confidence::High => "High",
                crate::rules::Confidence::Medium => "Medium",
                crate::rules::Confidence::Low => "Low",
            };
            let stable = stable_id(f.rule_id, path, f.line_number, &f.code_snippet);
            serde_json::json!({
                "id": stable,
                "category": "sast",
                "name": f.title,
                "message": f.title,
                "description": format!("{}\n\n**Offending code:**\n```\n{}\n```", f.recommendation, f.code_snippet.trim()),
                "severity": severity,
                "confidence": confidence,
                "scanner": { "id": "grackle", "name": "grackle" },
                "location": { "file": path, "start_line": f.line_number, "end_line": f.line_number },
                "identifiers": identifiers,
                "solution": f.remediation,
                "tracking": {
                    "type": "source",
                    "items": [{
                        "file": path,
                        "line_start": f.line_number,
                        "line_end": f.line_number,
                        "signatures": [{
                            "algorithm": "scope_offset",
                            "value": format!("{path}|{}:{}", f.rule_id, f.line_number),
                        }],
                    }],
                },
            })
        })
        .collect();
    let doc = serde_json::json!({
        "version": "15.2.1",
        "vulnerabilities": vulns,
        "scan": {
            "scanner": {
                "id": "grackle",
                "name": "grackle",
                "url": "https://github.com/cpeoples/grackle",
                "vendor": { "name": "cpeoples" },
                "version": env!("CARGO_PKG_VERSION"),
            },
            "type": "sast",
            "status": "success",
        },
    });
    serde_json::to_string_pretty(&doc).unwrap()
}

/// Deterministic per-finding id from rule + location + snippet hash (FNV-1a),
/// stable across re-scans so GitLab dedup tracks the same vulnerability.
fn stable_id(rule_id: &str, path: &str, line: usize, snippet: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in format!("{rule_id}|{path}|{line}|{snippet}").bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{rule_id}:{hash:016x}")
}

fn junit(results: &[FileResult], total: usize) -> String {
    let mut cases = String::new();
    for (path, f) in flat(results) {
        cases.push_str(&format!(
            "  <testcase name=\"{}\" classname=\"{}\" file=\"{}\">\n    <failure message=\"{}\" type=\"{}\">{}</failure>\n  </testcase>\n",
            xml_escape(f.rule_id),
            xml_escape(path),
            xml_escape(path),
            xml_escape(&format!("{}:{} {}", path, f.line_number, f.title)),
            f.severity.as_str(),
            xml_escape(&format!("{}\n\n{}", f.recommendation, f.remediation)),
        ));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites>\n  <testsuite name=\"grackle\" tests=\"{total}\" failures=\"{total}\">\n{cases}  </testsuite>\n</testsuites>\n"
    )
}

fn csv(results: &[FileResult]) -> String {
    let mut out = String::from(
        "file,line,severity,confidence,rule_id,title,cwe,owasp,mitre_attack,recommendation\n",
    );
    for (path, f) in flat(results) {
        let m = &f.metadata;
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            csv_field(path),
            f.line_number,
            f.severity.as_str(),
            f.confidence.as_str(),
            csv_field(f.rule_id),
            csv_field(f.title),
            csv_field(&m.cwe.join(" ")),
            csv_field(&m.owasp_appsec.join(" ")),
            csv_field(&m.mitre_attack.join(" ")),
            csv_field(f.recommendation),
        ));
    }
    out
}

fn xml(results: &[FileResult]) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<findings>\n");
    for (path, f) in flat(results) {
        let m = &f.metadata;
        out.push_str(&format!(
            "  <finding rule-id=\"{}\" severity=\"{}\" confidence=\"{}\">\n    <file>{}</file>\n    <line>{}</line>\n    <title>{}</title>\n    <cwe>{}</cwe>\n    <owasp>{}</owasp>\n    <mitre-attack>{}</mitre-attack>\n    <recommendation>{}</recommendation>\n    <code-snippet>{}</code-snippet>\n    <remediation>{}</remediation>\n  </finding>\n",
            xml_escape(f.rule_id),
            f.severity.as_str(),
            f.confidence.as_str(),
            xml_escape(path),
            f.line_number,
            xml_escape(f.title),
            xml_escape(&m.cwe.join(", ")),
            xml_escape(&m.owasp_appsec.join(", ")),
            xml_escape(&m.mitre_attack.join(", ")),
            xml_escape(f.recommendation),
            xml_escape(&f.code_snippet),
            xml_escape(&f.remediation),
        ));
    }
    out.push_str("</findings>\n");
    out
}

/// Block-scalar YAML string, indented under `key:` at `indent` spaces.
fn yaml_block(value: &str, indent: usize) -> String {
    let pad = " ".repeat(indent);
    value
        .lines()
        .map(|l| format!("{pad}{l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// YAML scalar: a JSON string is valid YAML and escapes every special
/// character, so titles, paths, and ids with `:`, `#`, or quotes stay well
/// formed. Used for every user-controlled scalar the YAML report emits.
fn yaml_scalar(value: &str) -> String {
    serde_json::to_string(value).unwrap()
}

fn yaml_list(items: &[&str]) -> String {
    items
        .iter()
        .map(|s| yaml_scalar(s))
        .collect::<Vec<_>>()
        .join(", ")
}

fn yaml(results: &[FileResult]) -> String {
    let mut out = String::from("findings:\n");
    for (path, f) in flat(results) {
        let m = &f.metadata;
        out.push_str(&format!(
            "  - rule_id: {}\n    severity: {}\n    confidence: {}\n    file: {}\n    line: {}\n    title: {}\n    cwe: [{}]\n    owasp_appsec: [{}]\n    mitre_attack: [{}]\n    recommendation: {}\n    code_snippet: |-\n{}\n    remediation: |-\n{}\n",
            yaml_scalar(f.rule_id),
            f.severity.as_str(),
            f.confidence.as_str(),
            yaml_scalar(path),
            f.line_number,
            yaml_scalar(f.title),
            yaml_list(m.cwe),
            yaml_list(m.owasp_appsec),
            yaml_list(m.mitre_attack),
            yaml_scalar(f.recommendation),
            yaml_block(&f.code_snippet, 6),
            yaml_block(&f.remediation, 6),
        ));
    }
    if results.is_empty() {
        out.push_str("  []\n");
    }
    out
}

fn html(results: &[FileResult], total: usize) -> String {
    let mut rows = String::new();
    for (path, f) in flat(results) {
        let m = &f.metadata;
        rows.push_str(&format!(
            "<section class=\"finding {sev_class}\">\n<h2>{title} <code>{rule}</code></h2>\n<p><strong>{path}:{line}</strong> &middot; <span class=\"sev\">{sev}</span> &middot; confidence: {conf}</p>\n<p>CWE: {cwe} &middot; OWASP: {owasp} &middot; MITRE ATT&amp;CK: {mitre}</p>\n<pre class=\"remediation\">{rem}</pre>\n</section>\n",
            sev_class = f.severity.as_str().to_ascii_lowercase(),
            title = xml_escape(f.title),
            rule = xml_escape(f.rule_id),
            path = xml_escape(path),
            line = f.line_number,
            sev = f.severity.as_str(),
            conf = f.confidence.as_str(),
            cwe = xml_escape(&m.cwe.join(", ")),
            owasp = xml_escape(&m.owasp_appsec.join(", ")),
            mitre = xml_escape(&m.mitre_attack.join(", ")),
            rem = xml_escape(&f.remediation),
        ));
    }
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>grackle findings</title>\n<style>\nbody{{font-family:system-ui,sans-serif;margin:2rem;line-height:1.5}}\n.finding{{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}}\n.critical{{border-left:6px solid #b00020}}\n.high{{border-left:6px solid #d97706}}\n.sev{{font-weight:600}}\npre.remediation{{background:#0d1117;color:#e6edf3;padding:1rem;border-radius:6px;overflow:auto;white-space:pre-wrap}}\ncode{{background:#f3f4f6;padding:.1rem .3rem;border-radius:4px}}\n</style>\n</head>\n<body>\n<h1>grackle findings</h1>\n<p>{total} finding(s).</p>\n{rows}</body>\n</html>\n"
    )
}

/// CycloneDX 1.5 SBOM. grackle scans raw workflow files rather than a
/// dependency tree, so `components` is empty and each finding attaches to the
/// root component, deduped by rule id.
fn cyclonedx(results: &[FileResult]) -> String {
    let mut seen = HashSet::new();
    let mut vulns: Vec<serde_json::Value> = Vec::new();
    for (_, f) in flat(results) {
        if !seen.insert(f.rule_id) {
            continue;
        }
        let m = &f.metadata;
        let cwes: Vec<u32> = m
            .cwe
            .iter()
            .filter_map(|c| c.strip_prefix("CWE-").unwrap_or(c).parse().ok())
            .collect();
        let mut properties: Vec<serde_json::Value> = Vec::new();
        let tag_props = [
            ("compliance:cis", m.cis_controls),
            ("mitre:attack", m.mitre_attack),
            ("mitre:atlas", m.mitre_atlas),
            ("owasp:top10", m.owasp_appsec),
            ("owasp:llm-top10", m.owasp_llm),
            ("owasp:asvs", m.owasp_asvs),
        ];
        for (name, values) in tag_props {
            for v in values {
                properties.push(serde_json::json!({ "name": name, "value": v }));
            }
        }
        let severity = match f.severity {
            Severity::Critical => "critical",
            Severity::High => "high",
        };
        vulns.push(serde_json::json!({
            "bom-ref": format!("vuln-{}", f.rule_id),
            "id": f.rule_id,
            "source": { "name": "grackle", "url": "https://github.com/cpeoples/grackle" },
            "ratings": [{ "severity": severity, "method": "other" }],
            "description": f.title,
            "recommendation": f.recommendation,
            "cwes": cwes,
            "affects": [{ "ref": "root-component" }],
            "properties": properties,
        }));
    }
    let doc = serde_json::json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": format!("urn:uuid:{}", bom_serial(results)),
        "version": 1,
        "metadata": {
            "tools": { "components": [{
                "type": "application",
                "name": "grackle",
                "version": env!("CARGO_PKG_VERSION"),
                "purl": concat!("pkg:cargo/grackle@", env!("CARGO_PKG_VERSION")),
            }] },
            "component": { "type": "application", "bom-ref": "root-component", "name": "scanned-workflows", "version": "0.0.0" },
        },
        "components": [],
        "vulnerabilities": vulns,
    });
    serde_json::to_string_pretty(&doc).unwrap()
}

/// A deterministic UUID-shaped serial derived from the finding set, so repeat
/// scans of the same tree emit a byte-stable BOM (no random `uuid` dependency).
fn bom_serial(results: &[FileResult]) -> String {
    let mut hash: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    for (path, f) in flat(results) {
        for b in format!("{path}|{}|{}", f.rule_id, f.line_number).bytes() {
            hash ^= b as u128;
            hash = hash.wrapping_mul(0x0000_0000_0100_0000_0000_0000_0000_013b);
        }
    }
    let h = format!("{hash:032x}");
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::metadata::RCE_CRITICAL;
    use crate::rules::Confidence;
    use std::path::PathBuf;

    fn results() -> Vec<FileResult> {
        vec![FileResult {
            path: PathBuf::from(".github/workflows/ci.yml"),
            findings: vec![Finding {
                rule_id: "fork_triggerable_test_agent",
                severity: Severity::Critical,
                title: "Fork-triggerable agent",
                confidence: Confidence::High,
                line_number: 12,
                locations: vec![12],
                recommendation: "Gate the agent.",
                metadata: RCE_CRITICAL,
                code_snippet: "run: agent".into(),
                remediation: "fix".into(),
            }],
        }]
    }

    #[test]
    fn json_carries_confidence_and_score() {
        let out = json(&results());
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v[0]["confidence"], "high");
        assert_eq!(v[0]["confidence_score"], 0.9);
    }

    #[test]
    fn gitlab_sast_uses_capitalized_confidence() {
        let v: serde_json::Value = serde_json::from_str(&gitlab_sast(&results())).unwrap();
        assert_eq!(v["vulnerabilities"][0]["confidence"], "High");
    }

    #[test]
    fn csv_and_text_show_confidence() {
        assert!(csv(&results())
            .lines()
            .next()
            .unwrap()
            .contains("confidence"));
        assert!(text(&results(), 1).contains("(high confidence)"));
    }
}
