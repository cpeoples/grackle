//! Compliance metadata attached to every finding.
//!
//! The fork-triggerable-agent rules all draw from two taxonomy profiles: a
//! CRITICAL remote-code-execution profile (a bare shell/write grant is a direct
//! RCE primitive) and a HIGH repository-mutation profile (a scoped `gh`/MCP
//! write verb can tamper with the repo but is not arbitrary execution). Keeping
//! them here as two shared constructors avoids copying the taxonomy arrays
//! across every rule.

/// Control-framework references for a finding.
#[derive(Debug, Clone, Copy)]
pub struct Metadata {
    pub cwe: &'static [&'static str],
    pub owasp_appsec: &'static [&'static str],
    pub owasp_llm: &'static [&'static str],
    pub owasp_asvs: &'static [&'static str],
    pub mitre_attack: &'static [&'static str],
    pub mitre_atlas: &'static [&'static str],
    pub cis_controls: &'static [&'static str],
    pub nist_controls: &'static [&'static str],
    pub pci_dss: &'static [&'static str],
    pub soc2: &'static [&'static str],
}

/// Profile for agents that gain arbitrary command execution or file writes:
/// the injection reaches a shell/write sink, so it is a direct RCE primitive.
pub const RCE_CRITICAL: Metadata = Metadata {
    cwe: &["CWE-77", "CWE-94", "CWE-269", "CWE-1427"],
    owasp_appsec: &["A01:2021", "A03:2021", "A08:2021"],
    owasp_llm: &["LLM01", "LLM02", "LLM06"],
    owasp_asvs: &["V1.2.2", "V6.2.1"],
    mitre_attack: &["T1059", "T1204.001", "T1552.001", "T1195.002"],
    mitre_atlas: &["AML.T0051", "AML.T0051.001", "AML.T0053", "AML.T0050"],
    cis_controls: &["CIS-6.1", "CIS-16.11"],
    nist_controls: &["AC-3", "AC-6", "CM-7", "SI-10"],
    pci_dss: &["6.2.4", "7.2.1", "8.6.2"],
    soc2: &["CC6.1", "CC6.3", "CC7.1"],
};

/// Profile for agents granted scoped repository-mutating GitHub tools (a
/// `gh pr/issue` write verb or an MCP write verb): repository tampering without
/// arbitrary execution.
pub const REPO_MUTATION_HIGH: Metadata = Metadata {
    cwe: &["CWE-77", "CWE-269", "CWE-284", "CWE-1427"],
    owasp_appsec: &["A01:2021", "A08:2021"],
    owasp_llm: &["LLM01", "LLM02", "LLM06"],
    owasp_asvs: &["V1.2.2", "V6.2.1"],
    mitre_attack: &["T1204.001", "T1195.002", "T1565.001"],
    mitre_atlas: &["AML.T0051", "AML.T0053", "AML.T0050"],
    cis_controls: &["CIS-6.1", "CIS-16.11"],
    nist_controls: &["AC-3", "AC-6", "SI-10"],
    pci_dss: &["6.2.4", "7.2.1"],
    soc2: &["CC6.1", "CC6.3", "CC7.1"],
};

/// Profile for an agent given an arbitrary shell on untrusted fork code in a
/// job that also exposes a secret, but with no provable repository write: the
/// shell is a command-execution primitive whose primary reachable harm is
/// reading and exfiltrating the injected credential. Shares the RCE execution
/// references with [`RCE_CRITICAL`] and adds the credential-access ones
/// (`CWE-522` insufficiently protected credentials, `T1552`
/// unsecured-credentials), scored HIGH rather than CRITICAL because the repo
/// cannot be shown to be directly writable from the file.
pub const SECRET_EXFIL_HIGH: Metadata = Metadata {
    cwe: &["CWE-77", "CWE-94", "CWE-522", "CWE-1427"],
    owasp_appsec: &["A01:2021", "A03:2021", "A08:2021"],
    owasp_llm: &["LLM01", "LLM02", "LLM06"],
    owasp_asvs: &["V1.2.2", "V6.2.1"],
    mitre_attack: &["T1059", "T1552", "T1552.001", "T1204.001"],
    mitre_atlas: &["AML.T0051", "AML.T0051.001", "AML.T0055"],
    cis_controls: &["CIS-6.1", "CIS-16.11"],
    nist_controls: &["AC-3", "AC-6", "CM-7", "IA-5"],
    pci_dss: &["6.2.4", "7.2.1", "8.6.2"],
    soc2: &["CC6.1", "CC6.3", "CC7.1"],
};
