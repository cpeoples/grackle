//! HTTP I/O for MR/PR comment posting. The only module here that touches the
//! network beyond [`super::inline`]. Every error is redacted before logging.

use crate::comment::context::{Platform, PlatformContext};
use crate::comment::fingerprint::{decode_marker, Marker};
use crate::comment::http::{agent, get_json, github_headers, gitlab_headers, send_json};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Outcome of [`post_or_update_comment`], reduced to what the CLI logs.
pub struct CommentResult {
    pub updated: bool,
    pub comment_url: Option<String>,
    pub previous_findings_count: Option<i64>,
    pub error: Option<String>,
}

/// The files changed in this MR/PR, or `None` when the platform call fails.
/// Used to scope the scan to the diff so comments do not flag pre-existing
/// issues on untouched files.
pub fn fetch_changed_files(ctx: &PlatformContext) -> Option<Vec<String>> {
    let agent = agent();
    let result = match ctx.platform {
        Platform::GitHub => github_changed_files(&agent, ctx),
        Platform::GitLab => gitlab_changed_files(&agent, ctx),
    };
    match result {
        Ok(files) => Some(files),
        Err(e) => {
            eprintln!(
                "grackle: could not fetch changed files from {}: {e}",
                ctx.platform.as_str()
            );
            None
        }
    }
}

fn github_changed_files(agent: &ureq::Agent, ctx: &PlatformContext) -> Result<Vec<String>, String> {
    let headers = github_headers(ctx);
    let mut files = Vec::new();
    for page in 1..=50 {
        let url = format!(
            "{}/repos/{}/pulls/{}/files?per_page=100&page={page}",
            ctx.api_url, ctx.project_ref, ctx.mr_number
        );
        let chunk = get_json(agent, &url, &headers, &ctx.token)?;
        let entries = chunk.as_array().cloned().unwrap_or_default();
        if entries.is_empty() {
            break;
        }
        for entry in &entries {
            let status = entry.get("status").and_then(Value::as_str).unwrap_or("");
            if status == "removed" {
                continue;
            }
            if let Some(fp) = entry.get("filename").and_then(Value::as_str) {
                files.push(fp.to_string());
            }
        }
        if entries.len() < 100 {
            break;
        }
    }
    Ok(files)
}

fn gitlab_changed_files(agent: &ureq::Agent, ctx: &PlatformContext) -> Result<Vec<String>, String> {
    let headers = gitlab_headers(ctx);
    let url = format!(
        "{}/projects/{}/merge_requests/{}/changes",
        ctx.api_url, ctx.project_ref, ctx.mr_number
    );
    let data = get_json(agent, &url, &headers, &ctx.token)?;
    Ok(gitlab_change_paths(data.get("changes")))
}

fn gitlab_change_paths(changes: Option<&Value>) -> Vec<String> {
    changes
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter(|c| {
                    !c.get("deleted_file")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                })
                .filter_map(|c| {
                    c.get("new_path")
                        .or_else(|| c.get("old_path"))
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `{file: {added or context line numbers}}` for the MR diff, used to decide
/// which findings can anchor an inline comment. `None` on failure; callers then
/// skip inline placement and rely on the summary comment.
pub fn fetch_diff_lines(ctx: &PlatformContext) -> Option<BTreeMap<String, Vec<usize>>> {
    let agent = agent();
    let result = match ctx.platform {
        Platform::GitHub => github_diff_lines(&agent, ctx),
        Platform::GitLab => gitlab_diff_lines(&agent, ctx),
    };
    match result {
        Ok(map) => Some(map),
        Err(e) => {
            eprintln!(
                "grackle: could not fetch diff lines from {}: {e}",
                ctx.platform.as_str()
            );
            None
        }
    }
}

fn github_diff_lines(
    agent: &ureq::Agent,
    ctx: &PlatformContext,
) -> Result<BTreeMap<String, Vec<usize>>, String> {
    let headers = github_headers(ctx);
    let mut out: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for page in 1..=50 {
        let url = format!(
            "{}/repos/{}/pulls/{}/files?per_page=100&page={page}",
            ctx.api_url, ctx.project_ref, ctx.mr_number
        );
        let chunk = get_json(agent, &url, &headers, &ctx.token)?;
        let entries = chunk.as_array().cloned().unwrap_or_default();
        if entries.is_empty() {
            break;
        }
        for entry in &entries {
            let status = entry.get("status").and_then(Value::as_str).unwrap_or("");
            let patch = entry.get("patch").and_then(Value::as_str).unwrap_or("");
            let Some(fp) = entry.get("filename").and_then(Value::as_str) else {
                continue;
            };
            if status == "removed" || patch.is_empty() {
                continue;
            }
            out.entry(fp.to_string())
                .or_default()
                .extend(added_lines_from_patch(patch));
        }
        if entries.len() < 100 {
            break;
        }
    }
    Ok(out)
}

fn gitlab_diff_lines(
    agent: &ureq::Agent,
    ctx: &PlatformContext,
) -> Result<BTreeMap<String, Vec<usize>>, String> {
    let headers = gitlab_headers(ctx);
    let base = format!(
        "{}/projects/{}/merge_requests/{}",
        ctx.api_url, ctx.project_ref, ctx.mr_number
    );

    // Prefer the canonical (untruncated) diff from the latest version.
    let versions = get_json(agent, &format!("{base}/versions"), &headers, &ctx.token)?;
    if let Some(version_id) = versions
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.get("id"))
        .and_then(Value::as_i64)
    {
        let detail = get_json(
            agent,
            &format!("{base}/versions/{version_id}"),
            &headers,
            &ctx.token,
        )?;
        let out = parse_gitlab_diffs(detail.get("diffs"));
        if !out.is_empty() {
            return Ok(out);
        }
    }

    let changes = get_json(agent, &format!("{base}/changes"), &headers, &ctx.token)?;
    Ok(parse_gitlab_diffs(changes.get("changes")))
}

fn parse_gitlab_diffs(entries: Option<&Value>) -> BTreeMap<String, Vec<usize>> {
    let mut out: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let Some(entries) = entries.and_then(Value::as_array) else {
        return out;
    };
    for entry in entries {
        if entry
            .get("deleted_file")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            continue;
        }
        let fp = entry
            .get("new_path")
            .or_else(|| entry.get("old_path"))
            .and_then(Value::as_str);
        let diff = entry.get("diff").and_then(Value::as_str).unwrap_or("");
        if let (Some(fp), false) = (fp, diff.is_empty()) {
            out.entry(fp.to_string())
                .or_default()
                .extend(added_lines_from_patch(diff));
        }
    }
    out
}

/// Added and context line numbers (new-file side) from a unified diff hunk. A
/// finding adjacent to a change still anchors to a hunk the reviewer can see.
fn added_lines_from_patch(patch: &str) -> Vec<usize> {
    let mut lines = Vec::new();
    let mut new_ln = 0usize;
    for raw in patch.lines() {
        if let Some(rest) = raw.strip_prefix("@@ ") {
            if let Some(plus) = rest.split_once('+').map(|(_, r)| r) {
                let num: String = plus.chars().take_while(|c| c.is_ascii_digit()).collect();
                new_ln = num.parse().unwrap_or(0);
            }
            continue;
        }
        if raw.is_empty() || new_ln == 0 {
            continue;
        }
        match raw.as_bytes()[0] {
            b'-' => {}
            b'+' | b' ' => {
                lines.push(new_ln);
                new_ln += 1;
            }
            _ => {}
        }
    }
    lines
}

/// The decoded marker of a previous grackle comment on this MR/PR, or `None`.
/// A transient failure here drops only the delta line, never the comment.
pub fn fetch_existing_marker(ctx: &PlatformContext) -> Option<Marker> {
    let agent = agent();
    match ctx.platform {
        Platform::GitHub => find_github_existing(&agent, ctx)
            .ok()
            .flatten()
            .map(|(_, m)| m),
        Platform::GitLab => find_gitlab_existing(&agent, ctx)
            .ok()
            .flatten()
            .map(|(_, m)| m),
    }
}

/// Post a new summary comment, or update the one carrying our marker. Never
/// panics: any failure returns a `CommentResult` with `error` set so the scan
/// exit code stays driven by findings.
pub fn post_or_update_comment(ctx: &PlatformContext, body: &str) -> CommentResult {
    let agent = agent();
    let result = match ctx.platform {
        Platform::GitHub => github_post_or_update(&agent, ctx, body),
        Platform::GitLab => gitlab_post_or_update(&agent, ctx, body),
    };
    result.unwrap_or_else(|e| {
        eprintln!(
            "grackle: MR comment to {} failed: {e}. Continuing.",
            ctx.platform.as_str()
        );
        CommentResult {
            updated: false,
            comment_url: None,
            previous_findings_count: None,
            error: Some(e),
        }
    })
}

fn github_post_or_update(
    agent: &ureq::Agent,
    ctx: &PlatformContext,
    body: &str,
) -> Result<CommentResult, String> {
    let headers = github_headers(ctx);
    let base = format!("{}/repos/{}", ctx.api_url, ctx.project_ref);
    let (existing_id, previous) = find_github_existing(agent, ctx)?.unzip();

    if let Some(id) = existing_id {
        let url = format!("{base}/issues/comments/{id}");
        let data = send_json(
            agent.patch(&url),
            &headers,
            json!({ "body": body }),
            &ctx.token,
        )?;
        return Ok(CommentResult {
            updated: true,
            comment_url: data
                .get("html_url")
                .and_then(Value::as_str)
                .map(str::to_string),
            previous_findings_count: previous.map(|m| m.findings_count),
            error: None,
        });
    }

    let url = format!("{base}/issues/{}/comments", ctx.mr_number);
    let data = send_json(
        agent.post(&url),
        &headers,
        json!({ "body": body }),
        &ctx.token,
    )?;
    Ok(CommentResult {
        updated: false,
        comment_url: data
            .get("html_url")
            .and_then(Value::as_str)
            .map(str::to_string),
        previous_findings_count: None,
        error: None,
    })
}

fn find_github_existing(
    agent: &ureq::Agent,
    ctx: &PlatformContext,
) -> Result<Option<(u64, Marker)>, String> {
    let headers = github_headers(ctx);
    let base = format!("{}/repos/{}", ctx.api_url, ctx.project_ref);
    for page in 1..=10 {
        let url = format!(
            "{base}/issues/{}/comments?per_page=100&page={page}",
            ctx.mr_number
        );
        let comments = get_json(agent, &url, &headers, &ctx.token)?;
        let comments = comments.as_array().cloned().unwrap_or_default();
        if comments.is_empty() {
            return Ok(None);
        }
        for c in &comments {
            let body = c.get("body").and_then(Value::as_str).unwrap_or("");
            if let Some(marker) = decode_marker(body) {
                let id = c.get("id").and_then(Value::as_u64).unwrap_or(0);
                return Ok(Some((id, marker)));
            }
        }
        if comments.len() < 100 {
            return Ok(None);
        }
    }
    Ok(None)
}

fn gitlab_post_or_update(
    agent: &ureq::Agent,
    ctx: &PlatformContext,
    body: &str,
) -> Result<CommentResult, String> {
    let headers = gitlab_headers(ctx);
    let base = format!(
        "{}/projects/{}/merge_requests/{}",
        ctx.api_url, ctx.project_ref, ctx.mr_number
    );
    let (existing_id, previous) = find_gitlab_existing(agent, ctx)?.unzip();

    if let Some(id) = existing_id {
        let url = format!("{base}/notes/{id}");
        send_json(
            agent.put(&url),
            &headers,
            json!({ "body": body }),
            &ctx.token,
        )?;
        return Ok(CommentResult {
            updated: true,
            comment_url: gitlab_note_url(ctx, id),
            previous_findings_count: previous.map(|m| m.findings_count),
            error: None,
        });
    }

    let url = format!("{base}/notes");
    let data = send_json(
        agent.post(&url),
        &headers,
        json!({ "body": body }),
        &ctx.token,
    )?;
    let note_id = data.get("id").and_then(Value::as_u64);
    Ok(CommentResult {
        updated: false,
        comment_url: note_id.and_then(|id| gitlab_note_url(ctx, id)),
        previous_findings_count: None,
        error: None,
    })
}

fn find_gitlab_existing(
    agent: &ureq::Agent,
    ctx: &PlatformContext,
) -> Result<Option<(u64, Marker)>, String> {
    let headers = gitlab_headers(ctx);
    let base = format!(
        "{}/projects/{}/merge_requests/{}",
        ctx.api_url, ctx.project_ref, ctx.mr_number
    );
    for page in 1..=10 {
        let url = format!("{base}/notes?per_page=100&page={page}&sort=desc&order_by=updated_at");
        let notes = get_json(agent, &url, &headers, &ctx.token)?;
        let notes = notes.as_array().cloned().unwrap_or_default();
        if notes.is_empty() {
            return Ok(None);
        }
        for n in &notes {
            if n.get("system").and_then(Value::as_bool).unwrap_or(false) {
                continue;
            }
            let body = n.get("body").and_then(Value::as_str).unwrap_or("");
            if let Some(marker) = decode_marker(body) {
                let id = n.get("id").and_then(Value::as_u64).unwrap_or(0);
                return Ok(Some((id, marker)));
            }
        }
        if notes.len() < 100 {
            return Ok(None);
        }
    }
    Ok(None)
}

fn gitlab_note_url(ctx: &PlatformContext, note_id: u64) -> Option<String> {
    let project_path = std::env::var("CI_PROJECT_PATH").ok()?;
    let server_url = std::env::var("CI_SERVER_URL").ok()?;
    let server_url = server_url.trim_end_matches('/');
    if project_path.is_empty() || server_url.is_empty() {
        return None;
    }
    Some(format!(
        "{server_url}/{project_path}/-/merge_requests/{}#note_{note_id}",
        ctx.mr_number
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_added_lines_from_patch() {
        let patch = "@@ -1,2 +3,4 @@\n context\n+added\n-removed\n more";
        assert_eq!(added_lines_from_patch(patch), vec![3, 4, 5]);
    }

    #[test]
    fn gitlab_change_paths_skips_deleted() {
        let changes = json!([
            {"new_path": "a.yml", "deleted_file": false},
            {"new_path": "b.yml", "deleted_file": true},
            {"old_path": "c.yml"}
        ]);
        assert_eq!(gitlab_change_paths(Some(&changes)), vec!["a.yml", "c.yml"]);
    }
}
