#!/usr/bin/env python3
"""Generate the Hugo documentation site for grackle.

Source of truth:
  * ``grackle --rules-json`` for the rule catalog (id, severity, family,
    agent, compliance metadata) so the published rule pages always match the
    shipped binary.
  * ``docs/*.md`` for long-form prose pages.
  * ``WHITEPAPER.md`` at the repo root, copied in as a docs page so the site
    tracks it without a second copy living under ``docs/``.

Run from the repo root (the docs workflow does), or from anywhere; paths are
resolved relative to this file.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve()
HUGO_DIR = HERE.parent.parent
REPO_ROOT = HUGO_DIR.parent
CONTENT_DIR = HUGO_DIR / "content"
STATIC_DIR = HUGO_DIR / "static"
STATIC_ASSETS_DIR = STATIC_DIR / "assets"
STATIC_IMAGES_DIR = STATIC_DIR / "images"
DOCS_DIR = REPO_ROOT / "docs"
DOCS_ASSETS_DIR = DOCS_DIR / "assets"
WHITEPAPER = REPO_ROOT / "WHITEPAPER.md"

BUILD_TIMESTAMP = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# GitHub Pages serves the site under a project subpath (/grackle/), passed in
# as HUGO_BASEURL. Asset URLs written into raw HTML bypass Hugo's relURL
# rewriting, so they must carry the base prefix themselves.
BASE_URL = os.environ.get("HUGO_BASEURL", "/").strip()
ASSET_URL_PREFIX = (BASE_URL.rstrip("/") or "") + "/assets/"

# Human display names for families the rule id cannot spell nicely on its own.
AGENT_DISPLAY = {
    "cursor": "Cursor",
    "opencode": "OpenCode",
    "amp": "Amp",
    "goose": "Goose",
    "droid": "Factory Droid",
    "aider": "Aider",
    "openhands": "OpenHands",
    "qwen code": "Qwen Code",
    "crush": "Crush",
    "copilot cli": "GitHub Copilot CLI",
    "continue cli": "Continue CLI",
    "gptme": "gptme",
    "swe": "SWE-agent",
    "warp": "Warp",
    "claude cli": "Claude Code CLI",
    "gemini cli": "Gemini CLI",
    "ai": "Generic action write/exec tools",
    "gemini or copilot": "Gemini / Copilot action",
    "codex": "Codex sandbox",
    "pr": "PR-Agent",
    "gitlab ci": "GitLab CI agent",
}

CONCERN_TITLES = {
    "installed": "Installed agents",
    "action": "Action-configured agents",
    "shell-exec": "Shell-exec secret exposure",
    "gitlab": "GitLab CI",
}
CONCERN_WEIGHTS = {"installed": 10, "action": 20, "shell-exec": 25, "gitlab": 30}

# Official homepage / action / docs for each agent family, keyed by the same
# agent string the rule catalog emits. When a key is present the rule table
# links the agent name to its source; families without a single canonical page
# (the generic write/exec, bespoke, and GitLab rows) are intentionally omitted.
AGENT_URL = {
    "cursor": "https://cursor.com/",
    "opencode": "https://github.com/sst/opencode",
    "amp": "https://ampcode.com/",
    "goose": "https://github.com/block/goose",
    "droid": "https://factory.ai/",
    "aider": "https://aider.chat/",
    "openhands": "https://github.com/All-Hands-AI/OpenHands",
    "qwen code": "https://github.com/QwenLM/qwen-code",
    "crush": "https://github.com/charmbracelet/crush",
    "copilot cli": "https://github.com/github/copilot-cli",
    "continue cli": "https://github.com/continuedev/continue",
    "gptme": "https://github.com/gptme/gptme",
    "swe": "https://github.com/SWE-agent/SWE-agent",
    "warp": "https://www.warp.dev/",
    "devin": "https://devin.ai/",
    "kilocode": "https://github.com/Kilo-Org/kilocode",
    "claude cli": "https://github.com/anthropics/claude-code",
    "gemini cli": "https://github.com/google-gemini/gemini-cli",
    "codemie": "https://codemie.ai/",
    "gemini or copilot": "https://github.com/google-github-actions/run-gemini-cli",
    "codex": "https://github.com/openai/codex",
    "junie agent with prompt bypass": "https://github.com/JetBrains/junie-github-action",
    "bonk agent with write token": "https://github.com/ask-bonk/ask-bonk",
    "cogni": "https://github.com/Cogni-AI-OU/cogni-ai-agent-action",
    "letta agent opened to forks": "https://github.com/letta-ai/letta-code-action",
    "code": "https://github.com/potproject/code-agent",
    "a5c": "https://github.com/a5c-ai/action",
    "iflow agent with prompt": "https://github.com/iflow-ai/iflow-cli-action",
    "sweep": "https://sweep.dev/",
    "pr": "https://github.com/qodo-ai/pr-agent",
}


def resolve_framework_url(kind: str, raw: str) -> str | None:
    """Canonical deep-link for a compliance id, or None if not linkable."""
    s = raw.strip()
    if kind == "cwe":
        m = re.match(r"CWE-(\d+)$", s)
        return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html" if m else None
    if kind == "mitre_attack":
        m = re.match(r"T(\d{4})(?:\.(\d{3}))?$", s)
        if not m:
            return None
        base = f"https://attack.mitre.org/techniques/T{m.group(1)}"
        return f"{base}/{m.group(2)}/" if m.group(2) else f"{base}/"
    if kind == "mitre_atlas":
        m = re.match(r"AML\.T(\d{4})(?:\.(\d{3}))?$", s)
        if not m:
            return None
        tid = f"AML.T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")
        return f"https://atlas.mitre.org/techniques/{tid}"
    if kind == "owasp_appsec":
        m = re.match(r"A(\d{2}):2021$", s)
        slugs = {
            "01": "A01_2021-Broken_Access_Control",
            "03": "A03_2021-Injection",
            "08": "A08_2021-Software_and_Data_Integrity_Failures",
        }
        return f"https://owasp.org/Top10/{slugs[m.group(1)]}/" if m and m.group(1) in slugs else "https://owasp.org/Top10/"
    if kind == "owasp_llm":
        return "https://genai.owasp.org/llm-top-10/"
    if kind == "owasp_asvs":
        return "https://owasp.org/www-project-application-security-verification-standard/"
    if kind == "nist_controls":
        return "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_2_0/home"
    if kind == "cis_controls":
        return "https://www.cisecurity.org/controls/cis-controls-list"
    if kind == "pci_dss":
        return "https://www.pcisecuritystandards.org/document_library/"
    if kind == "soc2":
        return "https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2"
    return None


# (json field, chip css class, url kind, row label) in render order: structural
# taxonomies first, then compliance mappings. Each field renders as its own
# labeled row in the Frameworks cell.
CHIP_FIELDS = (
    ("cwe", "framework-chip-cwe", "cwe", "CWE"),
    ("mitre_attack", "framework-chip-mitre", "mitre_attack", "ATT&CK"),
    ("mitre_atlas", "framework-chip-mitre", "mitre_atlas", "ATLAS"),
    ("owasp_appsec", "framework-chip-owasp", "owasp_appsec", "OWASP Top 10"),
    ("owasp_llm", "framework-chip-owasp", "owasp_llm", "OWASP LLM"),
    ("owasp_asvs", "framework-chip-asvs", "owasp_asvs", "ASVS"),
    ("nist_controls", "framework-chip-nist", "nist_controls", "NIST 800-53"),
    ("cis_controls", "framework-chip-cis", "cis_controls", "CIS"),
)


def framework_chips(compliance: dict) -> str:
    """One labeled row per framework category, chips wrapping within the row."""
    rows: list[str] = []
    for field, css, kind, label in CHIP_FIELDS:
        chips = [
            f'<a class="framework-chip {css}" href="{url}" '
            f'target="_blank" rel="noopener">{raw}</a>'
            for raw in compliance.get(field) or []
            if (url := resolve_framework_url(kind, raw))
        ]
        if not chips:
            continue
        rows.append(
            '<div class="framework-row">'
            f'<span class="framework-label">{label}</span>'
            f'<span class="framework-chip-group">{"".join(chips)}</span>'
            "</div>"
        )
    if not rows:
        return '<span class="framework-chip-empty">n/a</span>'
    return '<div class="framework-chips">' + "".join(rows) + "</div>"


def severity_badge(severity: str) -> str:
    return f'<span class="severity-{severity.lower()}">{severity}</span>'


def agent_display(agent: str) -> str:
    name = AGENT_DISPLAY.get(agent, agent.title())
    url = AGENT_URL.get(agent)
    return f"[{name}]({url})" if url else name


def load_rules() -> list[dict]:
    """Build grackle and ask it for the rule catalog as JSON."""
    binary = os.environ.get("GRACKLE_BIN")
    if binary:
        out = subprocess.run([binary, "--rules-json"], capture_output=True, text=True, check=True)
    else:
        out = subprocess.run(
            ["cargo", "run", "--quiet", "--", "--rules-json"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        )
    return json.loads(out.stdout)["rules"]


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    print(f"  wrote {path.relative_to(HUGO_DIR)}")


def build_rule_pages(rules: list[dict]) -> None:
    """One section index plus one page per agent family, grouped by concern."""
    print("Generating rule pages from --rules-json...")
    rules_dir = CONTENT_DIR / "rules"
    if rules_dir.exists():
        shutil.rmtree(rules_dir)

    by_concern: dict[str, list[dict]] = {}
    for r in rules:
        by_concern.setdefault(r["concern"], []).append(r)

    crit = sum(1 for r in rules if r["severity"] == "CRITICAL")
    high = sum(1 for r in rules if r["severity"] == "HIGH")
    index = (
        f'---\ntitle: "Detection Rules"\nweight: 100\ncollapsibleMenu: true\n'
        f'alwaysopen: false\nlastmod: "{BUILD_TIMESTAMP}"\n---\n\n'
        f"grackle ships **{len(rules)} rules** covering fork-triggerable AI coding "
        f"agents that can write to the repository: **{crit} critical**, **{high} high**. "
        "Each rule fires only when a workflow is fork-reachable, has no author gate, "
        "and runs the agent in a job that can mutate the repository.\n\n"
        "Rules are grouped by how they are post-filtered, not by vendor:\n\n"
        "- **Installed agents** anchor on an agent CLI or action name and confirm the "
        "family with a whole-file proof.\n"
        "- **Action-configured agents** anchor on an action opened to forks "
        "(write sandbox, `allowed_non_write_users: \"*\"`, and similar).\n"
        "- **Shell-exec secret exposure** flags an agent handed an arbitrary shell "
        "in a fork-reachable job that carries a secret it could exfiltrate.\n"
        "- **GitLab CI** rules use GitLab-native reachability rather than the GitHub "
        "`on:`/`permissions:` model.\n"
    )
    write(rules_dir / "_index.md", index)

    for concern, group in sorted(by_concern.items(), key=lambda kv: CONCERN_WEIGHTS.get(kv[0], 99)):
        title = CONCERN_TITLES.get(concern, concern.title())
        rows = "\n".join(
            f"| {agent_display(r['agent'])} | {severity_badge(r['severity'])} "
            f"| `{r['id']}` | {framework_chips(r['compliance'])} |"
            for r in sorted(group, key=lambda r: r["agent"])
        )
        page = (
            f'---\ntitle: "{title}"\nweight: {CONCERN_WEIGHTS.get(concern, 99)}\n'
            f'lastmod: "{BUILD_TIMESTAMP}"\n---\n\n'
            f"{len(group)} rule(s) in this group.\n\n"
            '<div class="pattern-table">\n\n'
            "| Agent | Severity | Rule ID | Frameworks |\n"
            "|---|---|---|---|\n"
            f"{rows}\n\n"
            "</div>\n"
        )
        write(rules_dir / f"{concern}.md", page)


def build_prose_pages() -> None:
    """Copy docs/*.md into content/, plus the root whitepaper."""
    print("Generating prose pages...")
    doc_pages = {
        "cli": ("CLI Reference", 200),
        "output-formats": ("Output Formats", 210),
        "detection-model": ("Detection Model", 220),
        "remediations": ("Remediations", 225),
        "ci-cd": ("CI/CD Integration", 230),
        "limitations": ("Limitations", 240),
    }
    for slug, (title, weight) in doc_pages.items():
        src = DOCS_DIR / f"{slug}.md"
        if not src.exists():
            print(f"  skip {slug} (docs/{slug}.md missing)")
            continue
        body = strip_badges(strip_leading_h1(src.read_text()))
        front = f'---\ntitle: "{title}"\nweight: {weight}\nlastmod: "{BUILD_TIMESTAMP}"\n---\n\n'
        write(CONTENT_DIR / f"{slug}.md", front + body)

    if WHITEPAPER.exists():
        body = strip_badges(strip_leading_h1(WHITEPAPER.read_text()))
        front = f'---\ntitle: "White Paper"\nweight: 300\nlastmod: "{BUILD_TIMESTAMP}"\n---\n\n'
        write(CONTENT_DIR / "whitepaper.md", front + body)


def strip_leading_h1(text: str) -> str:
    """Drop a leading ``# Title`` line; the Hugo front-matter supplies it."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip():
            if line.startswith("# "):
                return "\n".join(lines[i + 1 :]).lstrip("\n")
            break
    return text


BADGES_BLOCK = re.compile(
    r"<!--\s*BADGES_START.*?BADGES_END\s*-->\s*", re.DOTALL
)


def strip_badges(text: str) -> str:
    """Drop the README badge block (and its markers) from rendered docs pages.

    The badges are GitHub-README furniture (shields.io status images that only
    resolve against the repo); the Hugo site has its own chrome, so any page
    sourced from a README-style file gets the block removed.
    """
    return BADGES_BLOCK.sub("", text)


def copy_docs_assets() -> None:
    """Mirror docs/assets into static/assets and seed the favicon/logo.

    The README-sourced landing page and the Hugo chrome both reference brand
    art under docs/assets; Hugo serves static/ at the site root, so the files
    are copied there and the square mark is seeded as the favicon and sidebar
    logo.
    """
    if not DOCS_ASSETS_DIR.exists():
        return
    if STATIC_ASSETS_DIR.exists():
        shutil.rmtree(STATIC_ASSETS_DIR)
    STATIC_ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    copied = 0
    for src in DOCS_ASSETS_DIR.iterdir():
        if src.is_file():
            shutil.copy2(src, STATIC_ASSETS_DIR / src.name)
            copied += 1
    print(f"Copied {copied} asset(s) -> static/assets/")

    mark = DOCS_ASSETS_DIR / "grackle-mark.svg"
    if mark.exists():
        STATIC_IMAGES_DIR.mkdir(parents=True, exist_ok=True)
        for name in ("favicon.svg", "logo.svg"):
            shutil.copy2(mark, STATIC_IMAGES_DIR / name)
        print("Seeded favicon/logo from grackle-mark.svg -> static/images/")


def build_landing(rules: list[dict]) -> None:
    """Write the site landing page with a live rule count."""
    src = DOCS_DIR / "index.md"
    if src.exists():
        body = strip_badges(strip_leading_h1(src.read_text()))
    else:
        body = "See the [detection rules](/rules/) and [white paper](/whitepaper/)."
    count = len(rules)
    families = len({r["agent"] for r in rules})
    front = (
        '---\ntitle: "Grackle: Fork-Triggerable AI Agent Scanner for CI"\n'
        'linkTitle: "Grackle"\n'
        'description: "Standalone scanner that detects fork-triggerable AI coding '
        'agents with repository write access in GitHub Actions and GitLab CI. '
        f'{count} rules across {families} agent families, with SARIF, GitLab SAST, and '
        'CycloneDX output and dynamic remediations."\n'
        "weight: 1\nalwaysopen: true\n"
        f'lastmod: "{BUILD_TIMESTAMP}"\n---\n\n'
    )
    hero = (
        '<p class="brand-hero" align="center">'
        f'<img class="brand-hero-dark" src="{ASSET_URL_PREFIX}brand-mark.svg" alt="Grackle" width="480" />'
        f'<img class="brand-hero-light" src="{ASSET_URL_PREFIX}brand-mark-light.svg" alt="Grackle" width="480" />'
        "</p>\n\n"
    )
    body = body.replace("<!--RULES-->", "").replace("<!--/RULES-->", "")
    body = body.replace("<!--FAMILIES-->", "").replace("<!--/FAMILIES-->", "")
    body = body.replace('"docs/assets/', f'"{ASSET_URL_PREFIX}').replace(
        "(docs/assets/", f"({ASSET_URL_PREFIX}"
    )
    write(CONTENT_DIR / "_index.md", front + hero + body)


def main() -> None:
    CONTENT_DIR.mkdir(parents=True, exist_ok=True)
    rules = load_rules()
    print(f"Loaded {len(rules)} rules from grackle.")
    copy_docs_assets()
    build_landing(rules)
    build_rule_pages(rules)
    build_prose_pages()
    print("Docs generation complete.")


if __name__ == "__main__":
    main()
