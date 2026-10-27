#!/usr/bin/env python3
"""Validate an evidence bundle produced by capture_run.py.

The validator checks internal consistency: the manifest matches the files, the counts in run.json match
the data, every alert has a status, every resolved alert links an event that is one of its ancestors, and
every context bucket's counts match the documents it contains.

It cannot prove the documents came from the cluster; it can prove the bundle does not lie about itself.

Usage:
    python3 tools/evidence/validate_run.py evidence/runs/run-1
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path

SCHEMAS = {"c0015.evidence.run/2", "c0015.evidence.run/3"}
STATES = {"resolved", "partial", "unresolved", "no_ancestors"}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def parse_ts(value) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def ancestors_of(alert: dict) -> list[dict]:
    source = alert.get("_source", {})
    value = source.get("kibana.alert.ancestors")
    if value is None:
        value = source.get("kibana", {}).get("alert", {}).get("ancestors")
    return value or []


def field(document, path, default=None):
    if not isinstance(document, dict):
        return default
    if path in document:
        return document[path]
    value = document
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]
    return value


def validate(bundle: Path) -> list[str]:
    errors: list[str] = []
    run_path, manifest_path = bundle / "run.json", bundle / "manifest.json"
    if not run_path.is_file():
        return [f"missing {run_path}"]
    if not manifest_path.is_file():
        return [f"missing {manifest_path}"]

    run = json.loads(run_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    if run.get("schema") not in SCHEMAS:
        errors.append(f"run schema {run.get('schema')!r} not in {sorted(SCHEMAS)}")
    if not run.get("capture_id"):
        errors.append("capture_id missing")
    if manifest.get("capture_id") != run.get("capture_id"):
        errors.append("manifest capture_id does not match run.json")
    start, end = parse_ts(field(run, "window.start")), parse_ts(field(run, "window.end"))
    if not start or not end:
        errors.append("window start/end missing or unparsable")
    elif start > end:
        errors.append("window is inverted")

    declared = {item["path"]: item["sha256"] for item in manifest.get("files", [])}
    on_disk = {str(p.relative_to(bundle)).replace("\\", "/") for p in bundle.rglob("*.json") if p.name != "manifest.json"}
    for path, expected in declared.items():
        target = bundle / path
        if not target.is_file():
            errors.append(f"manifest references a missing file: {path}")
        elif sha256_file(target) != expected:
            errors.append(f"checksum mismatch: {path}")
    for extra in sorted(on_disk - set(declared)):
        errors.append(f"file not covered by the manifest: {extra}")

    def load(rel: str, default):
        path = bundle / rel
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default

    alerts = load("alerts/c0015.json", [])
    other = load("alerts/other_rules.json", [])
    sources = load("sources/by_alert.json", {})
    status = load("sources/status.json", {})
    unresolved = load("sources/unresolved.json", [])

    if field(run, "alerts.c0015") != len(alerts):
        errors.append("run.json C0015 alert count does not match alerts/c0015.json")
    if field(run, "alerts.other") is not None and field(run, "alerts.other") != len(other):
        errors.append("run.json other-alert count does not match alerts/other_rules.json")

    by_rule: dict[str, int] = {}
    for alert in alerts:
        name = field(alert.get("_source", {}), "kibana.alert.rule.name", "unknown")
        by_rule[name] = by_rule.get(name, 0) + 1
    if field(run, "alerts.by_rule") and field(run, "alerts.by_rule") != by_rule:
        errors.append("run.json by_rule does not match the alert documents")

    if len(status) != len(alerts):
        errors.append(f"status has {len(status)} entries for {len(alerts)} alerts")
    for state in status.values():
        if state.get("state") not in STATES:
            errors.append(f"unknown alert state {state.get('state')!r}")

    resolved_docs = sum(len(v) for v in sources.values())
    if field(run, "sources.resolved_documents") != resolved_docs:
        errors.append("run.json resolved_documents does not match sources/by_alert.json")
    with_source = len([s for s in status.values() if s.get("events", 0) > 0])
    if field(run, "sources.alerts_with_source") != with_source:
        errors.append("run.json alerts_with_source does not match sources/status.json")
    if field(run, "sources.unresolved") != len(unresolved):
        errors.append("run.json unresolved count does not match sources/unresolved.json")

    for alert in alerts:
        alert_id = alert.get("_id")
        state = status.get(alert_id, {}).get("state")
        linked = sources.get(alert_id, [])
        events = [doc for doc in linked if doc.get("kind") == "event"]
        if state in {"resolved", "partial"} and not events:
            errors.append(f"{alert_id}: state {state} but no event document linked")
        if state == "resolved" and any(item.get("alert") == alert_id for item in unresolved):
            errors.append(f"{alert_id}: state resolved but listed as unresolved")
        if state == "no_ancestors" and linked:
            errors.append(f"{alert_id}: no_ancestors but documents linked")
        allowed = {(item.get("index"), item.get("id")) for item in ancestors_of(alert)}
        for doc in linked:
            if doc.get("kind") == "alert":
                for item in ancestors_of(doc):
                    allowed.add((item.get("index"), item.get("id")))
        if state == "resolved" and events:
            if not any((doc["_index"], doc["_id"]) in allowed for doc in events):
                errors.append(f"{alert_id}: resolved event is not on the alert's ancestor path")

    for name, info in (field(run, "context") or {}).items():
        payload = load(f"context/{name}.json", None)
        if payload is None:
            errors.append(f"context file missing: {name}")
            continue
        if payload.get("returned") != len(payload.get("hits", [])):
            errors.append(f"context {name}: returned does not match hits")
        if payload.get("total", 0) < payload.get("returned", 0):
            errors.append(f"context {name}: total smaller than returned")
        if payload.get("truncated") != (payload.get("returned", 0) < payload.get("total", 0)):
            errors.append(f"context {name}: truncated flag does not match counts")
        if info.get("returned") != payload.get("returned"):
            errors.append(f"context {name}: run.json count disagrees with the file")

    return errors


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_run.py <bundle-dir>")
        return 2
    bundle = Path(sys.argv[1])
    if not bundle.is_dir():
        print(f"not a directory: {bundle}")
        return 2
    errors = validate(bundle)
    if errors:
        print(f"BUNDLE INVALID: {bundle}")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(f"bundle valid: {bundle}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
