mod comment;
mod localaction;
mod report;
mod rules;
mod scanner;
mod workflow;

use clap::Parser;
use report::Format;
use std::path::PathBuf;
use std::process::ExitCode;

/// Detects fork-triggerable CI coding agents that can write to the repository.
#[derive(Parser)]
#[command(name = "grackle", version, about)]
struct Cli {
    /// File or directory to scan.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Output format: text, json, markdown, sarif, gitlab-sast, junit, csv,
    /// xml, yaml, html, cyclonedx. Defaults to text, or is inferred from
    /// --output's extension when that is given.
    #[arg(short, long)]
    format: Option<String>,

    /// Write the report to a file instead of stdout. The format is inferred
    /// from the extension unless --format is set.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Emit findings as JSON (shorthand for --format json).
    #[arg(long, conflicts_with = "format")]
    json: bool,

    /// Validate every built-in rule against its own examples and exit.
    #[arg(long)]
    self_test: bool,

    /// List every built-in rule (id, severity, title) and exit.
    #[arg(long)]
    list_rules: bool,

    /// Print the full rule catalog with compliance metadata as JSON and exit.
    /// The documentation generator consumes this.
    #[arg(long)]
    rules_json: bool,

    /// Print per-file scan diagnostics to stderr (candidates, findings, totals).
    #[arg(long)]
    debug: bool,

    /// Post a sticky summary comment and inline comments on the current GitHub
    /// pull request. Detects the PR from GitHub Actions env; reads the token
    /// from GRACKLE_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN.
    #[arg(long)]
    github_comment: bool,

    /// Post a sticky summary comment and inline comments on the current GitLab
    /// merge request. Detects the MR from GitLab CI env; reads the token from
    /// GRACKLE_GITLAB_TOKEN, GITLAB_TOKEN, or CI_JOB_TOKEN.
    #[arg(long)]
    gitlab_comment: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.list_rules {
        let engine = rules::Engine::new();
        for rule in engine.rules() {
            println!("[{}] {}\n  {}", rule.severity.as_str(), rule.id, rule.title);
        }
        println!("\n{} rules.", engine.rules().len());
        return ExitCode::SUCCESS;
    }

    if cli.rules_json {
        let engine = rules::Engine::new();
        println!("{}", report::rules_json(engine.rules()));
        return ExitCode::SUCCESS;
    }

    if cli.self_test {
        return match rules::Engine::new().self_test() {
            Ok(n) => {
                println!("self-test passed: {n} rules classify their examples correctly");
                ExitCode::SUCCESS
            }
            Err(failures) => {
                for f in &failures {
                    eprintln!("self-test: {f}");
                }
                ExitCode::FAILURE
            }
        };
    }

    let format = match resolve_format(&cli) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("grackle: {e}");
            return ExitCode::from(2);
        }
    };

    let results = match scanner::scan_path(&cli.path, cli.debug) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("grackle: {}: {e}", cli.path.display());
            return ExitCode::from(2);
        }
    };

    let total: usize = results.iter().map(|r| r.findings.len()).sum();
    let rendered = report::render(&results, total, format);

    if let Some(path) = &cli.output {
        if let Err(e) = std::fs::write(path, &rendered) {
            eprintln!("grackle: {}: {e}", path.display());
            return ExitCode::from(2);
        }
    } else {
        print!("{rendered}");
    }

    if cli.github_comment {
        comment::run(comment::context::Platform::GitHub, &results);
    }
    if cli.gitlab_comment {
        comment::run(comment::context::Platform::GitLab, &results);
    }

    if total > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Pick the output format: an explicit --format wins, then --json, then the
/// --output extension, then text.
fn resolve_format(cli: &Cli) -> Result<Format, String> {
    if let Some(f) = &cli.format {
        return Format::parse(f);
    }
    if cli.json {
        return Ok(Format::Json);
    }
    if let Some(path) = &cli.output {
        if let Some(f) = Format::from_path(path) {
            return Ok(f);
        }
    }
    Ok(Format::Text)
}
