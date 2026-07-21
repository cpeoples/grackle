//! Inline review comments placed on the offending diff lines.
//!
//! A finding is only anchored when its `(file, line)` is part of the MR/PR
//! diff, because both platforms reject a comment on a line they cannot map to
//! the diff. Each inline body carries a per-finding marker so a re-run updates
//! nothing new rather than posting duplicates.

use crate::comment::context::{Platform, PlatformContext};
use crate::comment::fingerprint::finding_fingerprint;
use crate::comment::http::{agent, get_json, github_headers, gitlab_headers, send_json};
use crate::comment::rendering::RenderFinding;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const INLINE_MARKER_PREFIX: &str = "<!-- grackle:inline:v1:";
const INLINE_MARKER_SUFFIX: &str = " -->";

/// Stamped into a rewritten body so a later run can tell "grackle already
/// closed this" from "still open". Kept separate from the fingerprint marker so
/// the dedup index keeps working unchanged.
const INLINE_RESOLVED_SENTINEL: &str = "<!-- grackle:inline:state:resolved -->";

/// Outcome of an inline-posting pass.
#[derive(Default)]
pub struct InlinePostResult {
    pub posted: usize,
    pub skipped_not_in_diff: usize,
    pub failed: usize,
}

fn inline_marker(fingerprint: &str) -> String {
    format!("{INLINE_MARKER_PREFIX}{fingerprint}{INLINE_MARKER_SUFFIX}")
}

fn inline_body(rf: &RenderFinding<'_>, fingerprint: &str) -> String {
    let f = rf.finding;
    format!(
        "**{}** \u{00b7} {} confidence \u{00b7} `{}` \u{00b7} {}\n\n{}\n\n{}",
        f.severity.as_str(),
        f.confidence.as_str(),
        f.rule_id,
        f.title,
        f.recommendation,
        inline_marker(fingerprint),
    )
}

/// Rewrite an open inline body into its closed-state form: swap the severity
/// header for a green RESOLVED line pinned to the fixing commit, and stamp a
/// resolved-state sentinel before the marker. The fingerprint marker is kept so
/// dedup still works, and the transform is idempotent on an already-closed body.
fn resolved_inline_body(original: &str, commit_sha: &str) -> String {
    let short = short_sha(commit_sha);
    let mut blocks: Vec<String> = original.split("\n\n").map(str::to_string).collect();

    if let Some(idx) = blocks.iter().position(|b| header_rule_id(b).is_some()) {
        let rule = header_rule_id(&blocks[idx]).unwrap_or_else(|| "this rule".to_string());
        blocks[idx] =
            format!("\u{2705} **RESOLVED** \u{00b7} `{rule}` \u{00b7} no longer found in `{short}`");
    }

    if !original.contains(INLINE_RESOLVED_SENTINEL) {
        let marker_idx = blocks
            .iter()
            .position(|b| b.contains(INLINE_MARKER_PREFIX))
            .unwrap_or(blocks.len());
        blocks.insert(marker_idx, INLINE_RESOLVED_SENTINEL.to_string());
    }

    blocks.join("\n\n")
}

/// The rule id from an inline header block (the token between backticks in
/// `**SEV** · <conf> confidence · \`rule\` · title`), or `None` if this block is
/// not a grackle inline header.
fn header_rule_id(block: &str) -> Option<String> {
    if !block.trim_start().starts_with("**") || !block.contains("confidence") {
        return None;
    }
    let after = block.split_once("confidence \u{00b7} `")?.1;
    let rule = after.split_once('`')?.0;
    Some(rule.to_string())
}

fn short_sha(sha: &str) -> String {
    let trimmed: String = sha.trim().chars().take(12).collect();
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed
    }
}

/// Post an inline comment per finding whose line is in the diff. `diff_lines`
/// maps a repo-relative path to the set of anchorable line numbers.
pub fn post_inline_comments(
    ctx: &PlatformContext,
    findings: &[RenderFinding<'_>],
    diff_lines: &BTreeMap<String, Vec<usize>>,
) -> InlinePostResult {
    let agent = agent();
    let existing = fetch_existing_fingerprints(&agent, ctx).unwrap_or_default();

    let mut result = InlinePostResult::default();
    for rf in findings {
        let fp = finding_fingerprint(rf.finding.rule_id, &rf.path, rf.finding.line_number);
        if existing.contains(&fp) {
            continue;
        }
        let anchorable = diff_lines
            .get(&rf.path)
            .is_some_and(|lines| lines.contains(&rf.finding.line_number));
        if !anchorable {
            result.skipped_not_in_diff += 1;
            continue;
        }
        let body = inline_body(rf, &fp);
        let ok = match ctx.platform {
            Platform::GitHub => {
                github_post_inline(&agent, ctx, &rf.path, rf.finding.line_number, &body)
            }
            Platform::GitLab => {
                gitlab_post_inline(&agent, ctx, &rf.path, rf.finding.line_number, &body)
            }
        };
        if ok {
            result.posted += 1;
        } else {
            result.failed += 1;
        }
    }
    result
}

/// Number of stale inline threads resolved on a run.
#[derive(Default)]
pub struct ResolveResult {
    pub resolved: usize,
    pub failed: usize,
}

/// Resolve any grackle inline thread whose finding no longer fires. `open` is
/// the set of fingerprints still present this run; a thread carrying a grackle
/// marker whose fingerprint is absent from `open` is collapsed as resolved (the
/// comment stays visible). Threads still open, or already resolved, are left
/// alone. Never fails the scan: platform errors are logged and swallowed.
pub fn resolve_stale_inline_comments(
    ctx: &PlatformContext,
    findings: &[RenderFinding<'_>],
) -> ResolveResult {
    let open: BTreeSet<String> = findings
        .iter()
        .map(|rf| finding_fingerprint(rf.finding.rule_id, &rf.path, rf.finding.line_number))
        .collect();
    let agent = agent();
    match ctx.platform {
        Platform::GitHub => github_resolve_stale(&agent, ctx, &open),
        Platform::GitLab => gitlab_resolve_stale(&agent, ctx, &open),
    }
}

/// GitHub review-thread resolution is a GraphQL-only mutation, so this is the
/// one place the comment subsystem leaves REST: list the PR's review threads,
/// keep the ones whose first comment carries a grackle marker for a fingerprint
/// that has cleared, and resolve each by node id.
fn github_resolve_stale(
    agent: &ureq::Agent,
    ctx: &PlatformContext,
    open: &BTreeSet<String>,
) -> ResolveResult {
    let mut result = ResolveResult::default();
    let threads = match github_grackle_threads(agent, ctx) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("grackle: could not list review threads to resolve: {e}");
            return result;
        }
    };
    for thread in threads {
        if thread.resolved || open.contains(&thread.fingerprint) {
            continue;
        }
        github_update_comment_body(agent, ctx, &thread);
        if github_resolve_thread(agent, ctx, &thread.node_id) {
            result.resolved += 1;
        } else {
            result.failed += 1;
        }
    }
    result
}

struct GithubThread {
    node_id: String,
    comment_id: String,
    body: String,
    resolved: bool,
    fingerprint: String,
}

/// Rewrite the thread's first comment into its RESOLVED form before it is
/// collapsed. Best-effort: a failed edit is logged and the resolve still runs.
fn github_update_comment_body(agent: &ureq::Agent, ctx: &PlatformContext, thread: &GithubThread) {
    if thread.body.contains(INLINE_RESOLVED_SENTINEL) || thread.comment_id.is_empty() {
        return;
    }
    let new_body = resolved_inline_body(&thread.body, &ctx.commit_sha);
    let mutation = format!(
        "mutation {{ updatePullRequestReviewComment(input: {{pullRequestReviewCommentId: \"{}\", body: {}}}) {{ pullRequestReviewComment {{ id }} }} }}",
        thread.comment_id,
        graphql_string(&new_body),
    );
    if let Err(e) = send_json(
        agent.post(&graphql_endpoint(&ctx.api_url)),
        &github_headers(ctx),
        json!({ "query": mutation }),
        &ctx.token,
    ) {
        eprintln!("grackle: could not rewrite resolved inline body: {e}");
    }
}

/// The PR's review threads that carry a grackle inline marker, paged through
/// GraphQL. Only the first comment of each thread is inspected, since that is
/// the one grackle authored.
fn github_grackle_threads(
    agent: &ureq::Agent,
    ctx: &PlatformContext,
) -> Result<Vec<GithubThread>, String> {
    let (owner, name) = ctx
        .project_ref
        .split_once('/')
        .ok_or_else(|| "GITHUB_REPOSITORY is not owner/name".to_string())?;
    let graphql_url = graphql_endpoint(&ctx.api_url);
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..20 {
        let after = cursor
            .as_deref()
            .map(|c| format!(", after: \"{c}\""))
            .unwrap_or_default();
        let query = format!(
            "query {{ repository(owner: \"{owner}\", name: \"{name}\") {{ \
             pullRequest(number: {}) {{ reviewThreads(first: 100{after}) {{ \
             pageInfo {{ hasNextPage endCursor }} \
             nodes {{ id isResolved comments(first: 1) {{ nodes {{ id body }} }} }} }} }} }} }}",
            ctx.mr_number
        );
        let data = send_json(
            agent.post(&graphql_url),
            &github_headers(ctx),
            json!({ "query": query }),
            &ctx.token,
        )?;
        let threads = data
            .pointer("/data/repository/pullRequest/reviewThreads")
            .ok_or_else(|| "unexpected GraphQL shape for reviewThreads".to_string())?;
        for node in threads
            .get("nodes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let body = node
                .pointer("/comments/nodes/0/body")
                .and_then(Value::as_str)
                .unwrap_or("");
            let Some(fingerprint) = decode_inline_marker(body) else {
                continue;
            };
            out.push(GithubThread {
                node_id: node.get("id").and_then(Value::as_str).unwrap_or("").to_string(),
                comment_id: node
                    .pointer("/comments/nodes/0/id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                body: body.to_string(),
                resolved: node.get("isResolved").and_then(Value::as_bool).unwrap_or(false),
                fingerprint,
            });
        }
        let page = threads.get("pageInfo");
        let has_next = page
            .and_then(|p| p.get("hasNextPage"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !has_next {
            break;
        }
        cursor = page
            .and_then(|p| p.get("endCursor"))
            .and_then(Value::as_str)
            .map(str::to_string);
        if cursor.is_none() {
            break;
        }
    }
    Ok(out)
}

fn github_resolve_thread(agent: &ureq::Agent, ctx: &PlatformContext, node_id: &str) -> bool {
    let mutation = format!(
        "mutation {{ resolveReviewThread(input: {{threadId: \"{node_id}\"}}) {{ thread {{ isResolved }} }} }}"
    );
    report_send(send_json(
        agent.post(&graphql_endpoint(&ctx.api_url)),
        &github_headers(ctx),
        json!({ "query": mutation }),
        &ctx.token,
    ))
}

/// Encode a Rust string as a GraphQL string literal (double-quoted, with the
/// escapes GraphQL requires). Used to inline a multi-line comment body into a
/// mutation without a separate variables payload.
fn graphql_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The GraphQL endpoint for a REST `api_url`. github.com's REST base is
/// `https://api.github.com`, whose GraphQL sibling is `/graphql`; GitHub
/// Enterprise uses `<host>/api/v3` for REST and `<host>/api/graphql` for
/// GraphQL.
fn graphql_endpoint(api_url: &str) -> String {
    let base = api_url.trim_end_matches('/');
    if let Some(host) = base.strip_suffix("/api/v3") {
        format!("{host}/api/graphql")
    } else {
        format!("{base}/graphql")
    }
}

/// GitLab discussion resolution is REST: list discussions, and for any whose
/// grackle-marked note has a cleared fingerprint and is not already resolved,
/// `PUT .../discussions/:id?resolved=true`.
fn gitlab_resolve_stale(
    agent: &ureq::Agent,
    ctx: &PlatformContext,
    open: &BTreeSet<String>,
) -> ResolveResult {
    let mut result = ResolveResult::default();
    for page in 1..=10 {
        let url = format!(
            "{}/projects/{}/merge_requests/{}/discussions?per_page=100&page={page}",
            ctx.api_url, ctx.project_ref, ctx.mr_number
        );
        let data = match get_json(agent, &url, &gitlab_headers(ctx), &ctx.token) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("grackle: could not list discussions to resolve: {e}");
                return result;
            }
        };
        let arr = data.as_array().cloned().unwrap_or_default();
        if arr.is_empty() {
            break;
        }
        for disc in &arr {
            let notes = disc.get("notes").and_then(Value::as_array);
            let first = notes.and_then(|n| n.first());
            let body = first.and_then(|n| n.get("body")).and_then(Value::as_str);
            let Some(fingerprint) = body.and_then(decode_inline_marker) else {
                continue;
            };
            let already = first
                .and_then(|n| n.get("resolved"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if already || open.contains(&fingerprint) {
                continue;
            }
            let Some(disc_id) = disc.get("id").and_then(Value::as_str) else {
                continue;
            };
            gitlab_rewrite_note(agent, ctx, disc_id, first);
            let put = format!(
                "{}/projects/{}/merge_requests/{}/discussions/{disc_id}?resolved=true",
                ctx.api_url, ctx.project_ref, ctx.mr_number
            );
            if report_send(send_json(
                agent.put(&put),
                &gitlab_headers(ctx),
                json!({}),
                &ctx.token,
            )) {
                result.resolved += 1;
            } else {
                result.failed += 1;
            }
        }
        if arr.len() < 100 {
            break;
        }
    }
    result
}

/// GitLab counterpart to [`github_update_comment_body`]: rewrite a discussion's
/// first note to its RESOLVED form before the discussion is resolved.
fn gitlab_rewrite_note(
    agent: &ureq::Agent,
    ctx: &PlatformContext,
    disc_id: &str,
    note: Option<&Value>,
) {
    let Some(note) = note else { return };
    let body = note.get("body").and_then(Value::as_str).unwrap_or("");
    if body.contains(INLINE_RESOLVED_SENTINEL) {
        return;
    }
    let Some(note_id) = note.get("id").and_then(Value::as_i64) else {
        return;
    };
    let new_body = resolved_inline_body(body, &ctx.commit_sha);
    let url = format!(
        "{}/projects/{}/merge_requests/{}/discussions/{disc_id}/notes/{note_id}",
        ctx.api_url, ctx.project_ref, ctx.mr_number
    );
    if let Err(e) = send_json(
        agent.put(&url),
        &gitlab_headers(ctx),
        json!({ "body": new_body }),
        &ctx.token,
    ) {
        eprintln!("grackle: could not rewrite resolved inline body: {e}");
    }
}

fn github_post_inline(
    agent: &ureq::Agent,
    ctx: &PlatformContext,
    path: &str,
    line: usize,
    body: &str,
) -> bool {
    let url = format!(
        "{}/repos/{}/pulls/{}/comments",
        ctx.api_url, ctx.project_ref, ctx.mr_number
    );
    let payload = json!({
        "body": body,
        "commit_id": ctx.commit_sha,
        "path": path,
        "line": line,
        "side": "RIGHT",
    });
    report_send(send_json(
        agent.post(&url),
        &github_headers(ctx),
        payload,
        &ctx.token,
    ))
}

fn gitlab_post_inline(
    agent: &ureq::Agent,
    ctx: &PlatformContext,
    path: &str,
    line: usize,
    body: &str,
) -> bool {
    let Some(refs) = gitlab_diff_refs(agent, ctx) else {
        return false;
    };
    let url = format!(
        "{}/projects/{}/merge_requests/{}/discussions",
        ctx.api_url, ctx.project_ref, ctx.mr_number
    );
    let payload = json!({
        "body": body,
        "position": {
            "base_sha": refs.0,
            "start_sha": refs.1,
            "head_sha": refs.2,
            "position_type": "text",
            "new_path": path,
            "old_path": path,
            "new_line": line,
        }
    });
    report_send(send_json(
        agent.post(&url),
        &gitlab_headers(ctx),
        payload,
        &ctx.token,
    ))
}

/// GitLab needs base/start/head SHAs from the latest MR diff version to anchor
/// a positioned discussion.
fn gitlab_diff_refs(
    agent: &ureq::Agent,
    ctx: &PlatformContext,
) -> Option<(String, String, String)> {
    let url = format!(
        "{}/projects/{}/merge_requests/{}/versions",
        ctx.api_url, ctx.project_ref, ctx.mr_number
    );
    let data = get_json(agent, &url, &gitlab_headers(ctx), &ctx.token).ok()?;
    let latest = data.as_array()?.first()?;
    let base = latest.get("base_commit_sha")?.as_str()?.to_string();
    let start = latest.get("start_commit_sha")?.as_str()?.to_string();
    let head = latest.get("head_commit_sha")?.as_str()?.to_string();
    Some((base, start, head))
}

/// Fingerprints already commented on this MR/PR, so a re-run does not duplicate.
fn fetch_existing_fingerprints(
    agent: &ureq::Agent,
    ctx: &PlatformContext,
) -> Option<BTreeSet<String>> {
    match ctx.platform {
        Platform::GitHub => github_existing_fingerprints(agent, ctx),
        Platform::GitLab => gitlab_existing_fingerprints(agent, ctx),
    }
}

fn github_existing_fingerprints(
    agent: &ureq::Agent,
    ctx: &PlatformContext,
) -> Option<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for page in 1..=10 {
        let url = format!(
            "{}/repos/{}/pulls/{}/comments?per_page=100&page={page}",
            ctx.api_url, ctx.project_ref, ctx.mr_number
        );
        let data = get_json(agent, &url, &github_headers(ctx), &ctx.token).ok()?;
        let arr = data.as_array().cloned().unwrap_or_default();
        if arr.is_empty() {
            break;
        }
        for c in &arr {
            if let Some(fp) = c
                .get("body")
                .and_then(Value::as_str)
                .and_then(decode_inline_marker)
            {
                out.insert(fp);
            }
        }
        if arr.len() < 100 {
            break;
        }
    }
    Some(out)
}

fn gitlab_existing_fingerprints(
    agent: &ureq::Agent,
    ctx: &PlatformContext,
) -> Option<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for page in 1..=10 {
        let url = format!(
            "{}/projects/{}/merge_requests/{}/discussions?per_page=100&page={page}",
            ctx.api_url, ctx.project_ref, ctx.mr_number
        );
        let data = get_json(agent, &url, &gitlab_headers(ctx), &ctx.token).ok()?;
        let arr = data.as_array().cloned().unwrap_or_default();
        if arr.is_empty() {
            break;
        }
        for disc in &arr {
            let notes = disc.get("notes").and_then(Value::as_array);
            for note in notes.into_iter().flatten() {
                if let Some(fp) = note
                    .get("body")
                    .and_then(Value::as_str)
                    .and_then(decode_inline_marker)
                {
                    out.insert(fp);
                }
            }
        }
        if arr.len() < 100 {
            break;
        }
    }
    Some(out)
}

fn decode_inline_marker(body: &str) -> Option<String> {
    let start = body.find(INLINE_MARKER_PREFIX)? + INLINE_MARKER_PREFIX.len();
    let rest = &body[start..];
    let end = rest.find(" -->")?;
    Some(rest[..end].to_string())
}

/// Turn a send result into a posted/failed bool, logging the redacted error.
fn report_send(result: Result<Value, String>) -> bool {
    match result {
        Ok(_) => true,
        Err(e) => {
            eprintln!("grackle: inline comment post failed: {e}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_marker_round_trips() {
        let m = inline_marker("0123456789abcdef");
        let body = format!("**HIGH** `rule`\n\ntext\n\n{m}");
        assert_eq!(
            decode_inline_marker(&body).as_deref(),
            Some("0123456789abcdef")
        );
    }

    #[test]
    fn no_marker_decodes_none() {
        assert!(decode_inline_marker("plain body").is_none());
    }

    #[test]
    fn graphql_endpoint_maps_rest_bases() {
        assert_eq!(
            graphql_endpoint("https://api.github.com"),
            "https://api.github.com/graphql"
        );
        assert_eq!(
            graphql_endpoint("https://ghe.example.com/api/v3"),
            "https://ghe.example.com/api/graphql"
        );
    }

    #[test]
    fn resolved_body_swaps_header_keeps_marker_and_stamps_sentinel() {
        let open = "**CRITICAL** \u{00b7} high confidence \u{00b7} `fork_agent` \u{00b7} A title\n\nDo the fix.\n\n<!-- grackle:inline:v1:abc123 -->";
        let closed = resolved_inline_body(open, "deadbeefcafebabe0000");
        assert!(closed.starts_with("\u{2705} **RESOLVED** \u{00b7} `fork_agent`"));
        assert!(closed.contains("no longer found in `deadbeefcafe`"));
        assert!(closed.contains("Do the fix."));
        assert!(closed.contains("<!-- grackle:inline:v1:abc123 -->"));
        assert!(closed.contains(INLINE_RESOLVED_SENTINEL));
        assert_eq!(decode_inline_marker(&closed).as_deref(), Some("abc123"));
    }

    #[test]
    fn resolved_body_is_idempotent() {
        let open = "**HIGH** \u{00b7} medium confidence \u{00b7} `r` \u{00b7} t\n\nfix\n\n<!-- grackle:inline:v1:ff -->";
        let once = resolved_inline_body(open, "abcdef123456");
        let twice = resolved_inline_body(&once, "abcdef123456");
        assert_eq!(once.matches(INLINE_RESOLVED_SENTINEL).count(), 1);
        assert_eq!(twice.matches(INLINE_RESOLVED_SENTINEL).count(), 1);
    }

    #[test]
    fn graphql_string_escapes_control_chars() {
        assert_eq!(graphql_string("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
    }
}
