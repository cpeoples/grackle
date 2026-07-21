//! Local (composite) action resolution.
//!
//! A workflow can hide an agent one level down: the workflow step is
//! `uses: ./.github/actions/foo`, and the real `aider --message "$UNTRUSTED"`
//! lives in that action's `action.yml`. Scanning only the workflow misses it.
//!
//! When grackle scans a directory (a checked-out repo), this module resolves
//! `uses: ./<path>` references to the referenced action definition so the
//! engine can look for an agent invocation inside it. Reachability, author
//! gating, and write capability still come from the *caller* workflow, since
//! that is where the trust boundary and token actually live. Resolution is one
//! level deep: an action that itself delegates to another `uses:` is not
//! followed further.

use std::path::{Path, PathBuf};

/// A `uses: ./<path>` reference found in a workflow, with the line it sits on.
pub struct LocalActionRef {
    /// 1-based line of the `uses:` in the caller workflow.
    pub line: usize,
    /// The repository-relative path from the `uses:` value (no leading `./`).
    pub rel_path: String,
}

/// Extract every `uses: ./<path>` reference from a workflow, with line numbers.
/// Only local references (leading `./`) are returned; remote `owner/repo@ref`
/// actions are resolved by GitHub, not by us.
pub fn local_action_refs(content: &str) -> Vec<LocalActionRef> {
    let mut refs = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed
            .strip_prefix("- uses:")
            .or_else(|| trimmed.strip_prefix("uses:"))
        else {
            continue;
        };
        let value = rest.trim().trim_matches(|c| c == '"' || c == '\'');
        if let Some(path) = value.strip_prefix("./") {
            let path = path.split(['@', ' ']).next().unwrap_or(path).trim();
            if !path.is_empty() {
                refs.push(LocalActionRef {
                    line: i + 1,
                    rel_path: path.to_string(),
                });
            }
        }
    }
    refs
}

/// Given the repository root and a repo-relative action path, return the action
/// definition file (`action.yml` / `action.yaml`) if it exists. A `uses: ./x`
/// path may point at a directory (containing `action.yml`) or directly at the
/// file.
pub fn resolve_action_file(repo_root: &Path, rel_path: &str) -> Option<PathBuf> {
    let base = repo_root.join(rel_path);
    if base.is_file() {
        return Some(base);
    }
    for name in ["action.yml", "action.yaml"] {
        let candidate = base.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Best-effort repository root for a scanned workflow path: the directory that
/// contains the `.github` folder the workflow lives under. Falls back to the
/// workflow's parent so resolution still works for unconventional layouts.
pub fn repo_root_for(workflow_path: &Path) -> PathBuf {
    let components: Vec<_> = workflow_path.components().collect();
    if let Some(pos) = components.iter().position(|c| c.as_os_str() == ".github") {
        let mut root = PathBuf::new();
        for c in &components[..pos] {
            root.push(c.as_os_str());
        }
        if root.as_os_str().is_empty() {
            return PathBuf::from(".");
        }
        return root;
    }
    workflow_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_local_refs_only() {
        let wf = concat!(
            "jobs:\n  a:\n    steps:\n",
            "      - uses: ./.github/actions/aider-run\n",
            "      - uses: actions/checkout@v4\n",
            "      - uses: './.github/actions/review'\n",
        );
        let refs = local_action_refs(wf);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].rel_path, ".github/actions/aider-run");
        assert_eq!(refs[0].line, 4);
        assert_eq!(refs[1].rel_path, ".github/actions/review");
    }

    #[test]
    fn repo_root_strips_github_and_below() {
        let p = Path::new("/tmp/myrepo/.github/workflows/ci.yml");
        assert_eq!(repo_root_for(p), PathBuf::from("/tmp/myrepo"));
    }
}
