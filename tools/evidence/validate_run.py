#!/usr/bin/env python3
"""Validate an evidence bundle produced by capture_run.py.

Checks the bundle against its own manifest and metadata. It proves the bundle is internally consistent
(same files, same counts, every alert linked or explicitly unresolved); it cannot prove the documents
came from the cluster.

Usage:
    python3 tools/evidence/validate_run.py evidence/runs/run-1-v2
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def parse_ts(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def validate(bundle: Path) -> list[str]:
    errors: list[str] = []
    run_path = bundle / "run.json"
    manifest_path = bundle / "manifest.json"
    if not run_path.is_file():
        return [f"missing {run_path}"]
    if not manifest_path.is_file():
        return [f"missing {manifest_path}"]

    run = json.loads(run_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    if run.get("schema") != "c0015.evidence.run/2":
        errors.append(f"run schema {run.get('schema')!r}")
    if not run.get("capture_id"):
        errors.append("capture_id missing")
    start, end = parse_ts(run.get("window", {}).get("start", "")), parse_ts(run.get("window", {}).get("end", ""))
    if not start or not end:
        errors.append("window start/end missing or unparsable")
    elif start > end:
        errors.append("window is inverted")

    declared = {f["path"]: f["sha256"] for f in manifest.get("files", [])}
    on_disk = {str(p.relative_to(bundle)).replace("\\", "/") for p in bundle.rglob("*.json") if p.name != "manifest.json"}
    for path, expected in declared.items():
        target = bundle / path
        if not target.is_file():
            errors.append(f"manifest references a missing file: {path}")
            continue
        if sha256_file(target) != expected:
            errors.append(f"checksum mismatch: {path}")
    for extra in sorted(on_disk - set(declared)):
        errors.append(f"file not covered by the manifest: {extra}")

    alerts_path = bundle / "alerts" / "c0015.json"
    if not alerts_path.is_file():
        errors.append("alerts/c0015.json missing")
        return errors
    alerts = json.loads(alerts_path.read_text(encoding="utf-8"))
    if run["alerts"]["c0015"] != len(alerts):
        errors.append(f"run.json says {run['alerts']['c0015']} C0015 alerts, file has {len(alerts)}")

    sources_path = bundle / "sources" / "by_alert.json"
    unresolved_path = bundle / "sources" / "unresolved.json"
    sources = json.loads(sources_path.read_text(encoding="utf-8")) if sources_path.is_file() else {}
    unresolved = json.loads(unresolved_path.read_text(encoding="utf-8")) if unresolved_path.is_file() else []
    unresolved_alerts = {item.get("alert") for item in unresolved}

    for alert in alerts:
        alert_id = alert.get("_id")
        linked = sources.get(alert_id) or []
        if not linked and alert_id not in unresolved_alerts:
            errors.append(f"alert {alert_id} has neither a source document nor an unresolved entry")
    if run.get("sources", {}).get("alerts_with_source") != len([a for a in alerts if sources.get(a.get("_id"))]):
        errors.append("alerts_with_source does not match by_alert.json")

    for name, info in run.get("context", {}).items():
        path = bundle / "context" / f"{name}.json"
        if not path.is_file():
            errors.append(f"context file missing: {name}")
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("returned") != info.get("returned"):
            errors.append(f"context {name} returned count disagrees with run.json")
        if payload.get("truncated") and not payload.get("sample"):
            errors.append(f"context {name} is truncated but not marked as a sample")
        if payload.get("total") == 0 and payload.get("returned") != 0:
            errors.append(f"context {name} reports zero total with hits")

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

