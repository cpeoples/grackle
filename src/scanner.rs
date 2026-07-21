//! Workflow file discovery and scan orchestration.

use crate::localaction::{repo_root_for, resolve_action_file};
use crate::rules::{Engine, Finding};
use crate::workflow::{calls_reusable_workflow, has_fork_reachable_trigger, is_workflow_call_only};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// A scanned file and the findings it produced.
pub struct FileResult {
    pub path: PathBuf,
    pub findings: Vec<Finding>,
}

/// Whether a path is a GitLab CI file (`.gitlab-ci.yml` or a per-component
/// variant). GitLab has no local composite-action construct, so these files
/// skip local-action resolution.
pub fn is_gitlab_ci(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name == ".gitlab-ci.yml"
        || name.ends_with(".gitlab-ci.yml")
        || name.ends_with(".gitlab-ci.yaml")
}

/// Whether a path looks like a CI workflow grackle should scan: GitHub Actions
/// workflows under `.github/workflows/`, and GitLab CI files (`.gitlab-ci.yml`
/// or a `*.gitlab-ci.yml` / `*.gitlab-ci.yaml` variant, which projects use for
/// per-component or example pipelines).
pub fn is_ci_workflow(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if is_gitlab_ci(path) {
        return true;
    }
    if !(name.ends_with(".yml") || name.ends_with(".yaml")) {
        return false;
    }
    path.components()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|w| w[0].as_os_str() == ".github" && w[1].as_os_str() == "workflows")
}

/// Whether any sibling workflow in `repo_root/.github/workflows` invokes the
/// reusable workflow at `callee` (via `uses: ./.github/workflows/<name>`) and
/// is itself fork-reachable. A reusable callee's exposure is entirely its
/// caller's, so this resolves the callee's real reachability from the repo on
/// disk. A caller that is another reusable workflow is followed one level: if
/// *it* has a fork-reachable caller, the chain is fork-reachable. Cross-repo
/// callers cannot be seen and are conservatively not assumed.
fn has_fork_reachable_caller(repo_root: &Path, callee: &Path) -> bool {
    let Some(callee_name) = callee.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let wf_dir = repo_root.join(".github").join("workflows");
    let mut chain_callees: Vec<String> = vec![callee_name.to_string()];
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Bounded breadth-first walk up the caller chain: a caller that merely
    // re-exposes the callee as another reusable workflow is followed until a
    // fork-reachable entry point is found or the chain is exhausted.
    while let Some(target) = chain_callees.pop() {
        if !visited.insert(target.clone()) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&wf_dir) else {
            return false;
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let p = entry.path();
            if p == callee || !is_ci_workflow(&p) {
                continue;
            }
            let Ok(caller) = std::fs::read_to_string(&p) else {
                continue;
            };
            if !calls_reusable_workflow(&caller, &target) {
                continue;
            }
            // A caller with a *direct* fork trigger (not merely `workflow_call`)
            // exposes the whole chain to fork contributors.
            if has_fork_reachable_trigger(&caller) && !is_workflow_call_only(&caller) {
                return true;
            }
            // The caller is reachable only via its own callers; enqueue it.
            if is_workflow_call_only(&caller) {
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    chain_callees.push(name.to_string());
                }
            }
        }
    }
    false
}

/// Scan a single file's contents with the given engine.
pub fn scan_content(engine: &Engine, content: &str) -> Vec<Finding> {
    engine.scan(content)
}

/// Walk `root` (a file or directory) and scan every CI workflow found. When
/// `debug` is set, per-file diagnostics are written to stderr so a run that
/// produces no findings can be distinguished from one that scanned no files.
pub fn scan_path(root: &Path, debug: bool) -> std::io::Result<Vec<FileResult>> {
    let engine = Engine::new();
    let mut results = Vec::new();

    let candidates: Vec<PathBuf> = if root.is_file() {
        vec![root.to_path_buf()]
    } else {
        WalkDir::new(root)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path())
            .filter(|p| is_ci_workflow(p))
            .collect()
    };

    if debug {
        eprintln!(
            "grackle: {} candidate workflow(s) under {}",
            candidates.len(),
            root.display()
        );
    }

    let mut scanned = 0usize;
    for path in candidates {
        let Ok(content) = std::fs::read_to_string(&path) else {
            if debug {
                eprintln!("grackle: skip (unreadable) {}", path.display());
            }
            continue;
        };
        scanned += 1;
        // GitHub Actions workflows can delegate to a local composite action;
        // resolve `uses: ./<path>` from disk so an agent hidden in an
        // action.yml is attributed to the caller. GitLab CI has no such
        // construct, so it uses the plain scan.
        let findings = if is_gitlab_ci(&path) {
            scan_content(&engine, &content)
        } else {
            let repo_root = repo_root_for(&path);
            // A reusable (`workflow_call`-only) workflow is reachable only
            // through a caller. Resolve whether any sibling workflow in the
            // same repo both invokes this file and is itself fork-reachable, so
            // an unreachable reusable callee is not reported as a confirmed
            // fork-triggerable finding.
            let caller_fork_reachable = if is_workflow_call_only(&content) {
                Some(has_fork_reachable_caller(&repo_root, &path))
            } else {
                None
            };
            engine.scan_with_repo(&content, caller_fork_reachable, |rel_path| {
                resolve_action_file(&repo_root, rel_path)
                    .and_then(|f| std::fs::read_to_string(f).ok())
            })
        };
        if debug {
            eprintln!(
                "grackle: {} finding(s) in {}",
                findings.len(),
                path.display()
            );
        }
        if !findings.is_empty() {
            results.push(FileResult { path, findings });
        }
    }

    if debug {
        eprintln!(
            "grackle: scanned {scanned} file(s), {} with findings",
            results.len()
        );
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn unique_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("grackle-test-{tag}-{nanos}"));
        fs::create_dir_all(dir.join(".github/workflows")).unwrap();
        dir
    }

    const REUSABLE_AGENT: &str = concat!(
        "name: reusable agent\n",
        "on:\n  workflow_call:\n    inputs:\n      issue_number:\n        type: string\n",
        "jobs:\n  run:\n    permissions:\n      contents: write\n    steps:\n",
        "      - env:\n          P: ${{ github.event.issue.body }}\n",
        "        run: claude -p \"$P\" --dangerously-skip-permissions\n",
    );

    #[test]
    fn reusable_callee_without_fork_reachable_caller_is_suppressed() {
        let dir = unique_dir("no-caller");
        let wf = dir.join(".github/workflows");
        fs::write(wf.join("agent.yml"), REUSABLE_AGENT).unwrap();
        // The only caller is itself reusable, so no fork contributor reaches it.
        fs::write(
            wf.join("dispatch.yml"),
            "on:\n  workflow_call:\njobs:\n  go:\n    uses: ./.github/workflows/agent.yml\n",
        )
        .unwrap();
        let results = scan_path(&dir, false).unwrap();
        let flagged: Vec<_> = results
            .iter()
            .filter(|r| r.path.ends_with("agent.yml"))
            .collect();
        assert!(flagged.is_empty(), "unreachable callee should not fire");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reusable_callee_with_fork_reachable_caller_still_fires() {
        let dir = unique_dir("fork-caller");
        let wf = dir.join(".github/workflows");
        fs::write(wf.join("agent.yml"), REUSABLE_AGENT).unwrap();
        // A fork-reachable caller wires the reusable agent, so it is reachable.
        fs::write(
            wf.join("on-comment.yml"),
            "on:\n  issue_comment:\n    types: [created]\njobs:\n  go:\n    uses: ./.github/workflows/agent.yml\n",
        )
        .unwrap();
        let results = scan_path(&dir, false).unwrap();
        let flagged = results.iter().any(|r| r.path.ends_with("agent.yml"));
        assert!(
            flagged,
            "callee with a fork-reachable caller must still fire"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reusable_callee_reached_through_a_caller_chain_still_fires() {
        let dir = unique_dir("chain");
        let wf = dir.join(".github/workflows");
        fs::write(wf.join("agent.yml"), REUSABLE_AGENT).unwrap();
        // mid.yml is reusable and calls the agent; entry.yml is fork-reachable
        // and calls mid.yml - the chain is reachable end to end.
        fs::write(
            wf.join("mid.yml"),
            "on:\n  workflow_call:\njobs:\n  go:\n    uses: ./.github/workflows/agent.yml\n",
        )
        .unwrap();
        fs::write(
            wf.join("entry.yml"),
            "on:\n  pull_request:\njobs:\n  go:\n    uses: ./.github/workflows/mid.yml\n",
        )
        .unwrap();
        let results = scan_path(&dir, false).unwrap();
        let flagged = results.iter().any(|r| r.path.ends_with("agent.yml"));
        assert!(flagged, "callee reached via a caller chain must still fire");
        fs::remove_dir_all(&dir).ok();
    }
}
