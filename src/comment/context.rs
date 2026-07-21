//! Platform detection and request context for MR/PR comments.
//!
//! Pure environment probing, no network. The token is read from environment
//! variables only and never logged: every path that could surface it routes
//! through `redact` first.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    GitHub,
    GitLab,
}

impl Platform {
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::GitHub => "github",
            Platform::GitLab => "gitlab",
        }
    }
}

/// Everything the commenter needs to talk to GitHub or GitLab, resolved from CI
/// environment variables. `token` is sensitive and must never be logged.
#[derive(Debug, Clone)]
pub struct PlatformContext {
    pub platform: Platform,
    pub api_url: String,
    pub project_ref: String,
    pub mr_number: u64,
    pub commit_sha: String,
    pub token: String,
    pub run_url: Option<String>,
}

/// Strip any token value from a message before it reaches a log line.
pub fn redact(msg: &str, token: &str) -> String {
    if token.is_empty() {
        return msg.to_string();
    }
    msg.replace(token, "***REDACTED***")
}

/// First non-empty environment variable from `names`.
fn first_env(names: &[&str]) -> Option<String> {
    names
        .iter()
        .filter_map(|n| std::env::var(n).ok())
        .find(|v| !v.is_empty())
}

/// Resolve the MR/PR context from CI environment variables, or `None` (with a
/// warning) when the platform is not active or required variables are missing.
pub fn detect_platform(want: Platform) -> Option<PlatformContext> {
    match want {
        Platform::GitHub => detect_github(),
        Platform::GitLab => detect_gitlab(),
    }
}

fn detect_github() -> Option<PlatformContext> {
    let token = first_env(&["GRACKLE_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"]);
    let Some(token) = token else {
        eprintln!(
            "grackle: --github-comment: no GitHub token in env \
             (GRACKLE_GITHUB_TOKEN, GITHUB_TOKEN, GH_TOKEN); skipping comment"
        );
        return None;
    };

    let repo = env_str("GITHUB_REPOSITORY");
    let server_url = env_or("GITHUB_SERVER_URL", "https://github.com");
    let server_url = server_url.trim_end_matches('/');
    let mut api_url = env_str("GITHUB_API_URL").trim_end_matches('/').to_string();
    if api_url.is_empty() {
        api_url = if server_url == "https://github.com" {
            "https://api.github.com".to_string()
        } else {
            format!("{server_url}/api/v3")
        };
    }

    let (pr_number, head_sha) = github_pr_context();
    let sha = head_sha.unwrap_or_else(|| env_str("GITHUB_SHA"));

    let Some(pr_number) = pr_number else {
        eprintln!(
            "grackle: --github-comment: PR context incomplete; this flag must run \
             inside a pull_request workflow"
        );
        return None;
    };
    if repo.is_empty() {
        eprintln!("grackle: --github-comment: GITHUB_REPOSITORY is unset");
        return None;
    }

    let run_url = match (
        std::env::var("GITHUB_SERVER_URL").ok(),
        std::env::var("GITHUB_RUN_ID").ok(),
    ) {
        (Some(server), Some(run_id)) if !server.is_empty() && !run_id.is_empty() => Some(format!(
            "{}/{repo}/actions/runs/{run_id}",
            server.trim_end_matches('/')
        )),
        _ => None,
    };

    Some(PlatformContext {
        platform: Platform::GitHub,
        api_url,
        project_ref: repo,
        mr_number: pr_number,
        commit_sha: sha,
        token,
        run_url,
    })
}

/// Parse the PR number and head-commit SHA from GitHub Actions env. The head
/// SHA (`pull_request.head.sha`) is preferred over `GITHUB_SHA` because the
/// latter is a synthetic merge commit that is garbage-collected after the PR
/// closes, breaking file:line deep links.
fn github_pr_context() -> (Option<u64>, Option<String>) {
    let mut pr_number = None;
    let mut head_sha = None;

    let git_ref = env_str("GITHUB_REF");
    if let Some(num) = git_ref
        .strip_prefix("refs/pull/")
        .and_then(|rest| rest.split('/').next())
        .and_then(|n| n.parse::<u64>().ok())
    {
        pr_number = Some(num);
    }

    let event_path = env_str("GITHUB_EVENT_PATH");
    if !event_path.is_empty() {
        if let Ok(text) = std::fs::read_to_string(&event_path) {
            if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&text) {
                let pr = payload.get("pull_request").or_else(|| payload.get("issue"));
                if pr_number.is_none() {
                    if let Some(n) = pr.and_then(|p| p.get("number")).and_then(|n| n.as_u64()) {
                        if n > 0 {
                            pr_number = Some(n);
                        }
                    }
                }
                if let Some(sha) = pr
                    .and_then(|p| p.get("head"))
                    .and_then(|h| h.get("sha"))
                    .and_then(|s| s.as_str())
                {
                    if !sha.trim().is_empty() {
                        head_sha = Some(sha.trim().to_string());
                    }
                }
            }
        }
    }
    (pr_number, head_sha)
}

fn detect_gitlab() -> Option<PlatformContext> {
    let token = first_env(&["GRACKLE_GITLAB_TOKEN", "GITLAB_TOKEN", "CI_JOB_TOKEN"]);
    let Some(token) = token else {
        eprintln!(
            "grackle: --gitlab-comment: no GitLab token in env \
             (GRACKLE_GITLAB_TOKEN, GITLAB_TOKEN, CI_JOB_TOKEN); skipping comment"
        );
        return None;
    };

    let mut api_url = env_str("CI_API_V4_URL").trim_end_matches('/').to_string();
    let server_url = env_str("CI_SERVER_URL");
    let server_url = server_url.trim_end_matches('/');
    if api_url.is_empty() && !server_url.is_empty() {
        api_url = format!("{server_url}/api/v4");
    }

    // On a forked-MR pipeline CI_PROJECT_ID is the fork; the Notes API must
    // target the upstream project (CI_MERGE_REQUEST_PROJECT_ID).
    let project_id = {
        let target = env_str("CI_MERGE_REQUEST_PROJECT_ID");
        if target.is_empty() {
            env_str("CI_PROJECT_ID")
        } else {
            target
        }
    };
    let mr_iid = env_str("CI_MERGE_REQUEST_IID");
    // On merge-train pipelines CI_COMMIT_SHA is synthetic and gets collected;
    // the source-branch head stays reachable for deep links.
    let sha = {
        let head = env_str("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA");
        if head.is_empty() {
            env_str("CI_COMMIT_SHA")
        } else {
            head
        }
    };

    if api_url.is_empty() || project_id.is_empty() || mr_iid.is_empty() {
        eprintln!(
            "grackle: --gitlab-comment: MR context incomplete; this flag must run \
             inside a merge_request_event pipeline"
        );
        return None;
    }

    let Ok(mr_number) = mr_iid.parse::<u64>() else {
        eprintln!("grackle: --gitlab-comment: CI_MERGE_REQUEST_IID is not an integer");
        return None;
    };

    let run_url = std::env::var("CI_JOB_URL").ok().filter(|s| !s.is_empty());

    Some(PlatformContext {
        platform: Platform::GitLab,
        api_url,
        project_ref: project_id,
        mr_number,
        commit_sha: sha,
        token,
        run_url,
    })
}

/// Browser-friendly link to `<file>:<line>` on the platform blob viewer, or
/// `None` when the commit SHA or web host cannot be derived.
pub fn file_deep_link(
    ctx: &PlatformContext,
    file_path: &str,
    line_number: usize,
) -> Option<String> {
    if file_path.is_empty() || ctx.commit_sha.is_empty() {
        return None;
    }
    let anchor = if line_number > 0 {
        format!("#L{line_number}")
    } else {
        String::new()
    };
    match ctx.platform {
        Platform::GitHub => {
            let mut server = "https://github.com".to_string();
            if !ctx.api_url.is_empty() && ctx.api_url != "https://api.github.com" {
                if let Some(base) = ctx.api_url.strip_suffix("/api/v3") {
                    server = base.to_string();
                }
            }
            Some(format!(
                "{server}/{}/blob/{}/{file_path}{anchor}",
                ctx.project_ref, ctx.commit_sha
            ))
        }
        Platform::GitLab => {
            let project_path = std::env::var("CI_PROJECT_PATH").ok()?;
            let server_url = env_str("CI_SERVER_URL");
            let server_url = server_url.trim_end_matches('/');
            if project_path.is_empty() || server_url.is_empty() {
                return None;
            }
            Some(format!(
                "{server_url}/{project_path}/-/blob/{}/{file_path}{anchor}",
                ctx.commit_sha
            ))
        }
    }
}

fn env_str(name: &str) -> String {
    std::env::var(name).unwrap_or_default().trim().to_string()
}

fn env_or(name: &str, default: &str) -> String {
    let v = std::env::var(name).unwrap_or_default();
    if v.is_empty() {
        default.to_string()
    } else {
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_removes_token() {
        assert_eq!(
            redact("auth ghp_secret failed", "ghp_secret"),
            "auth ***REDACTED*** failed"
        );
        assert_eq!(redact("no token here", ""), "no token here");
    }

    #[test]
    fn github_deep_link_uses_head_sha() {
        let ctx = PlatformContext {
            platform: Platform::GitHub,
            api_url: "https://api.github.com".into(),
            project_ref: "o/r".into(),
            mr_number: 5,
            commit_sha: "abc123".into(),
            token: "t".into(),
            run_url: None,
        };
        assert_eq!(
            file_deep_link(&ctx, ".github/workflows/ci.yml", 12).unwrap(),
            "https://github.com/o/r/blob/abc123/.github/workflows/ci.yml#L12"
        );
    }
}
