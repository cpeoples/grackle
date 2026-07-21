#!/usr/bin/env python3
"""Regenerate the rule and family counts in ``README.md`` and ``docs/index.md``.

The rule catalog is owned by the compiled binary, so the counts come from
``grackle --rules-json`` (built with ``cargo build`` if no ``GRACKLE_BIN`` is
set) rather than from any checked-in list. Run by the ``readme-rule-counts``
pre-commit hook whenever the rule sources, the README, or the landing page
change.

Exits non-zero if a file changes (pre-commit uses this to re-stage).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
README = ROOT / "README.md"
LANDING = ROOT / "docs" / "index.md"


def load_rules() -> list[dict]:
    binary = os.environ.get("GRACKLE_BIN")
    cmd = [binary, "--rules-json"] if binary else ["cargo", "run", "--quiet", "--", "--rules-json"]
    out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=True)
    return json.loads(out.stdout)["rules"]


def sub_marker(text: str, tag: str, value: int) -> str:
    return re.sub(rf"<!--{tag}-->\d+<!--/{tag}-->", f"<!--{tag}-->{value}<!--/{tag}-->", text)


def main() -> int:
    rules = load_rules()
    count = len(rules)
    families = len({r["agent"] for r in rules})

    changed = False

    readme = README.read_text()
    updated = sub_marker(readme, "RULES", count)
    updated = re.sub(r"(img\.shields\.io/badge/Rules-)\d+(-)", rf"\g<1>{count}\g<2>", updated)
    if updated != readme:
        README.write_text(updated)
        changed = True

    landing = LANDING.read_text()
    updated = sub_marker(landing, "RULES", count)
    updated = sub_marker(updated, "FAMILIES", families)
    if updated != landing:
        LANDING.write_text(updated)
        changed = True

    return 1 if changed else 0


if __name__ == "__main__":
    sys.exit(main())
