#!/usr/bin/env python3
"""Catalog tooling for the detection set.

The catalog is the single source of truth for the rule package: which rules ship, which are retired,
where each query lives, what it claims, and how it is deployed. Indexes and counts are generated from
it, never written by hand.

Usage:
    python3 tools/detections/catalog.py --check     # verify package, exit 1 on drift (CI)
    python3 tools/detections/catalog.py --update    # refresh hashes in the catalog
    python3 tools/detections/catalog.py --index     # write detections/INDEX.md

Checks performed by --check:
  * catalog parses against the expected schema version
  * every shipped rule points at a file that exists and is tracked by git
  * the recorded sha256 matches the file content
  * every .eql file under detections/eql is referenced exactly once
  * ids are unique, statuses and roles are from the allowed sets
  * no rule file is ignored by .gitignore (a clean clone must contain every shipped rule)
  * retired rules carry a reason and no file

The tool is deliberately stdlib-only so it runs on a bare runner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "detections" / "catalog.json"
INDEX = ROOT / "detections" / "INDEX.md"
RULE_DIR = ROOT / "detections" / "eql"

SCHEMA = "c0015.detections.catalog/1"
STATUSES = {"shipped", "retired"}
ROLES = {"alert", "building_block", "enrichment", "hunt"}


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)


def sha256(path: Path) -> str:
    """Hash the content with LF endings so a CRLF checkout matches the committed blob."""
    data = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def load() -> dict:
    if not CATALOG.exists():
        raise SystemExit(f"catalog not found: {CATALOG}")
    data = json.loads(CATALOG.read_text(encoding="utf-8"))
    if data.get("schema") != SCHEMA:
        raise SystemExit(f"catalog schema {data.get('schema')!r} != {SCHEMA!r}")
    return data


def check(data: dict) -> list[str]:
    errors: list[str] = []
    rules = data.get("rules", [])
    if not rules:
        errors.append("catalog has no rules")

    ids = [r.get("id") for r in rules]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        errors.append(f"duplicate ids: {sorted(duplicates)}")

    referenced: dict[str, str] = {}
    for rule in rules:
        rid = rule.get("id", "?")
        status = rule.get("status")
        role = rule.get("role")
        if status not in STATUSES:
            errors.append(f"{rid}: status {status!r} not in {sorted(STATUSES)}")
        if role not in ROLES:
            errors.append(f"{rid}: role {role!r} not in {sorted(ROLES)}")

        if status == "retired":
            if rule.get("file"):
                errors.append(f"{rid}: retired rules must not point at a file")
            if not rule.get("retirement", {}).get("reason"):
                errors.append(f"{rid}: retired rule needs a reason")
            continue

        file_rel = rule.get("file")
        if not file_rel:
            errors.append(f"{rid}: shipped rule has no file")
            continue
        if file_rel in referenced:
            errors.append(f"{rid}: file {file_rel} already used by {referenced[file_rel]}")
        referenced[file_rel] = rid

        path = ROOT / file_rel
        if not path.is_file():
            errors.append(f"{rid}: missing file {file_rel}")
            continue

        tracked = git("ls-files", "--error-unmatch", file_rel)
        if tracked.returncode != 0:
            errors.append(f"{rid}: {file_rel} is not tracked by git")

        ignored = git("check-ignore", "-q", file_rel)
        if ignored.returncode == 0:
            errors.append(f"{rid}: {file_rel} is ignored by .gitignore")

        recorded = rule.get("sha256")
        actual = sha256(path)
        if recorded and recorded != actual:
            errors.append(f"{rid}: sha256 drift for {file_rel}")

        if not rule.get("attck", {}).get("technique_id"):
            errors.append(f"{rid}: missing ATT&CK technique")

    on_disk = {str(p.relative_to(ROOT)).replace("\\", "/") for p in RULE_DIR.glob("*.eql")}
    for path in sorted(on_disk - set(referenced)):
        errors.append(f"orphan rule file not in catalog: {path}")
    for path in sorted(set(referenced) - on_disk):
        errors.append(f"catalog references a file that does not exist: {path}")

    return errors


def update_hashes(data: dict) -> None:
    for rule in data.get("rules", []):
        if rule.get("status") != "shipped":
            continue
        path = ROOT / rule["file"]
        if path.is_file():
            rule["sha256"] = sha256(path)


def render_index(data: dict) -> str:
    rules = [r for r in data.get("rules", []) if r.get("status") == "shipped"]
    retired = [r for r in data.get("rules", []) if r.get("status") == "retired"]
    roles = {}
    for r in rules:
        roles[r.get("role", "?")] = roles.get(r.get("role", "?"), 0) + 1

    lines = [
        "# Detection index",
        "",
        "Generated from [`catalog.json`](catalog.json) by `tools/detections/catalog.py`. Do not edit.",
        "",
        f"- shipped rules: **{len(rules)}**",
        f"- retired rules: **{len(retired)}**",
        "- roles: " + ", ".join(f"{k} {v}" for k, v in sorted(roles.items())),
        "",
        "| ID | Rule | Role | Severity | ATT&CK | Query |",
        "|---|---|---|---|---|---|",
    ]
    for r in sorted(rules, key=lambda x: x["id"]):
        attck = r.get("attck", {})
        lines.append(
            f"| {r['id']} | {r['name']} | {r.get('role')} | {r.get('severity')} "
            f"| {attck.get('technique_id','')} {attck.get('technique_name','')} "
            f"| [`{Path(r['file']).name}`](eql/{Path(r['file']).name}) |"
        )
    if retired:
        lines += ["", "## Retired", "", "| ID | Rule | Reason |", "|---|---|---|"]
        for r in retired:
            reason = r.get("retirement", {}).get("reason", "")
            lines.append(f"| {r['id']} | {r['name']} | {reason} |")
    lines.append("")
    return "\n".join(lines)



def render_coverage(data: dict) -> str:
    rules = [r for r in data.get("rules", []) if r.get("status") == "shipped"]
    lines = [
        "# ATT&CK coverage",
        "",
        "Generated from [`detections/catalog.json`](../../detections/catalog.json) by",
        "`tools/detections/catalog.py --coverage`. It records what each rule observes, not what the",
        "campaign achieved.",
        "",
        "| Tactic | Technique | Rule | Role | What the rule observes | Limitation |",
        "|---|---|---|---|---|---|",
    ]
    for r in sorted(rules, key=lambda x: x["id"]):
        a = r.get("attck", {})
        lines.append(
            f"| {a.get('tactic_name','')} | {a.get('technique_id','')} {a.get('technique_name','')} "
            f"| {r['id']} | {r.get('role')} | {r.get('description','')} | {r.get('limitations','')} |"
        )
    lines += [
        "",
        "## Not covered by a rule",
        "",
        "The lab exercises steps that no shipped rule detects: module download over HTTP, service",
        "installation (System channel, provider Service Control Manager), the scheduled task used as a",
        "foothold, and the transfer receipt at the cloud receiver. Those are listed here so the absence",
        "is explicit rather than implied.",
        "",
    ]
    return "\n".join(lines)

def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true")
    group.add_argument("--update", action="store_true")
    group.add_argument("--index", action="store_true")
    group.add_argument("--coverage", action="store_true")
    args = parser.parse_args()

    data = load()

    if args.update:
        update_hashes(data)
        CATALOG.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print("catalog hashes updated")

    if args.index:
        INDEX.write_text(render_index(data), encoding="utf-8")
        print(f"wrote {INDEX.relative_to(ROOT)}")
    if args.coverage:
        COVERAGE = ROOT / "docs" / "detection" / "attack-coverage.md"
        COVERAGE.write_text(render_coverage(data), encoding="utf-8")
        print(f"wrote {COVERAGE.relative_to(ROOT)}")

    if args.check or not (args.update or args.index or args.coverage):
        errors = check(data)
        if errors:
            print("PACKAGING CHECK FAILED")
            for e in errors:
                print(f"  - {e}")
            return 1
        print(f"packaging check passed ({len(data.get('rules', []))} catalog entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())




