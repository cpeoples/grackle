//! Merge-request / pull-request comment posting.
//!
//! Driven by `--github-comment` / `--gitlab-comment`. Platform detection is
//! env-based (see [`context::detect_platform`]); tokens are read from the
//! environment only, never from flags, and are redacted from every log line.
//!
//! The summary comment follows a dashboard-plus-drilldown shape and ends with a
//! stable HTML marker so a later scan updates the same comment in place instead
//! of posting duplicates. Inline comments are placed on the offending diff
//! lines when the platform can anchor them.

pub mod context;
pub mod fingerprint;
pub mod http;
pub mod inline;
pub mod posting;
pub mod rendering;

use crate::scanner::FileResult;
use context::{Platform, PlatformContext};

/// Detect the platform from CI env and, if active, post the summary comment and
/// inline comments for `results`. Never fails the scan: every error is logged
/// and swallowed so the exit code stays driven by findings.
pub fn run(platform: Platform, results: &[FileResult]) {
    let Some(ctx) = context::detect_platform(platform) else {
        return;
    };
    post(&ctx, results);
}

fn post(ctx: &PlatformContext, results: &[FileResult]) {
    let mut findings = rendering::collect(results, |p| p.to_string_lossy().replace('\\', "/"));

    // Scope comments to files touched by this MR/PR so we do not flag
    // pre-existing issues on untouched files. On fetch failure, comment on
    // everything found rather than silently posting nothing.
    if let Some(changed) = posting::fetch_changed_files(ctx) {
        let changed: std::collections::BTreeSet<&str> =
            changed.iter().map(String::as_str).collect();
        findings.retain(|rf| {
            changed.contains(rf.path.as_str()) || path_matches_suffix(&rf.path, &changed)
        });
    }

    let previous = posting::fetch_existing_marker(ctx);
    let body = rendering::render_comment_body(ctx, &findings, previous.as_ref());
    let result = posting::post_or_update_comment(ctx, &body);
    if result.error.is_none() {
        let verb = if result.updated { "updated" } else { "posted" };
        let delta = match result.previous_findings_count {
            Some(prev) => format!(" (was {prev}, now {})", findings.len()),
            None => String::new(),
        };
        match &result.comment_url {
            Some(url) => eprintln!("grackle: {verb} summary comment{delta}: {url}"),
            None => eprintln!("grackle: {verb} summary comment{delta}"),
        }
    }

    if !findings.is_empty() {
        if let Some(diff_lines) = posting::fetch_diff_lines(ctx) {
            let inline = inline::post_inline_comments(ctx, &findings, &diff_lines);
            eprintln!(
                "grackle: inline comments: {} posted, {} not in diff, {} failed",
                inline.posted, inline.skipped_not_in_diff, inline.failed
            );
        }
    }

    // Runs on every pass, including a clean one: threads whose finding cleared
    // are collapsed as resolved.
    let resolved = inline::resolve_stale_inline_comments(ctx, &findings);
    if resolved.resolved > 0 || resolved.failed > 0 {
        eprintln!(
            "grackle: resolved {} stale inline thread(s), {} failed",
            resolved.resolved, resolved.failed
        );
    }
}

/// The scanner reports paths relative to its scan root, which may sit below the
/// repo root the platform reports changed files against. Treat a finding as
/// changed when its path ends with any changed-file path (or vice versa).
fn path_matches_suffix(path: &str, changed: &std::collections::BTreeSet<&str>) -> bool {
    changed
        .iter()
        .any(|c| path.ends_with(c) || c.ends_with(path))
}
