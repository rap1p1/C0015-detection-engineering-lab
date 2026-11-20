#!/usr/bin/env python3
"""Check that relative markdown links point at tracked files.

External URLs are not fetched. Anchors are not resolved. The goal is to catch the packaging class of
error the review found: a README that links a rule file the clone does not contain.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LINK = re.compile(r"\]\(([^)\s]+)\)")
EXTERNAL = ("http://", "https://", "mailto:", "#")


def tracked() -> set[str]:
    result = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit("git ls-files failed")
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def main() -> int:
    files = tracked()
    broken: list[str] = []
    for md in sorted(p for p in files if p.endswith(".md")):
        text = (ROOT / md).read_text(encoding="utf-8", errors="replace")
        base = Path(md).parent
        for match in LINK.finditer(text):
            target = match.group(1)
            if target.startswith(EXTERNAL):
                continue
            target = target.split("#", 1)[0]
            if not target:
                continue
            resolved = (base / target).as_posix()
            # normalise ./ and ../ segments
            parts: list[str] = []
            for part in resolved.split("/"):
                if part in ("", "."):
                    continue
                if part == "..":
                    if parts:
                        parts.pop()
                    continue
                parts.append(part)
            normalised = "/".join(parts)
            if normalised not in files and not (ROOT / normalised).exists():
                broken.append(f"{md} -> {match.group(1)}")

    if broken:
        print(f"BROKEN LINKS ({len(broken)}):")
        for item in broken:
            print(f"  - {item}")
        return 1
    print(f"markdown links resolve ({sum(1 for f in files if f.endswith('.md'))} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
