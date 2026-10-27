#!/usr/bin/env python3
"""Validate an evidence export against the schema and the provenance rules.

The point of this tool is to make under-specified evidence fail loudly. It does not check that a
record is authentic; it checks that the export declares where it came from, that every record carries
the identity fields a query needs, that the capture kind is honest, and that synthetic data is labelled
as synthetic.

Usage:
    python3 tools/evidence/validate.py <export.json> [--allow-legacy]

Exit codes:
    0  export is structurally valid
    1  export is invalid
    2  file missing or unreadable
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "evidence" / "schema" / "export-v1.schema.json"
SCHEMA_ID = "c0015.evidence.export/1"
KINDS = {"live", "synthetic", "legacy_projected"}
REQUIRED_EVENT = ("code", "category", "provider", "channel")


def parse_ts(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def validate(export: dict, allow_legacy: bool) -> list[str]:
    errors: list[str] = []

    if export.get("schema") != SCHEMA_ID:
        errors.append(f"schema is {export.get('schema')!r}, expected {SCHEMA_ID!r}")

    capture = export.get("capture", {})
    kind = capture.get("capture_kind")
    if kind not in KINDS:
        errors.append(f"capture_kind {kind!r} not in {sorted(KINDS)}")
    if kind == "legacy_projected" and not allow_legacy:
        errors.append("legacy_projected export needs --allow-legacy and is not equivalent to a capture")
    for field in ("capture_id", "created_utc", "operator_note"):
        if not capture.get(field):
            errors.append(f"capture.{field} missing")

    source = export.get("source", {})
    for field in ("index", "query_hash", "window_start", "window_end"):
        if not source.get(field):
            errors.append(f"source.{field} missing")
    start = parse_ts(source.get("window_start", ""))
    end = parse_ts(source.get("window_end", ""))
    if start and end and start > end:
        errors.append("source window is inverted")

    records = export.get("records")
    if not isinstance(records, list) or not records:
        errors.append("records missing or empty")
        return errors

    seen = set()
    for i, rec in enumerate(records):
        where = f"records[{i}]"
        locator = (rec.get("_index"), rec.get("_id"))
        if not rec.get("_index") or not rec.get("_id"):
            errors.append(f"{where}: source locator incomplete")
        elif locator in seen:
            errors.append(f"{where}: duplicate locator {locator}")
        else:
            seen.add(locator)

        ts = parse_ts(rec.get("timestamp", ""))
        if ts is None:
            errors.append(f"{where}: timestamp missing or unparsable")
        elif start and end and not (start <= ts <= end):
            errors.append(f"{where}: timestamp outside the declared window")

        host = rec.get("host") or {}
        if not host.get("name"):
            errors.append(f"{where}: host.name missing")

        event = rec.get("event") or {}
        for field in REQUIRED_EVENT:
            if not event.get(field):
                errors.append(f"{where}: event.{field} missing")

        if kind == "synthetic" and not capture.get("operator_note", "").lower().startswith("synthetic"):
            errors.append(f"records from a synthetic capture must say so in capture.operator_note")

    return errors



def legacy_report(path: Path, export: dict) -> int:
    """Legacy exports predate the schema. Report what they cannot support instead of pretending."""
    meta_path = path.with_suffix(".meta.json")
    if not meta_path.is_file():
        print(f"LEGACY INVALID: {path} has no sidecar {meta_path.name} declaring its provenance")
        return 1
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if meta.get("capture_kind") != "legacy_projected":
        print(f"LEGACY INVALID: sidecar capture_kind is {meta.get('capture_kind')!r}")
        return 1

    records = export.get("records") if isinstance(export, dict) else None
    if records is None:
        # the legacy files are grouped dicts of records
        records = []
        for value in export.values() if isinstance(export, dict) else []:
            if isinstance(value, list):
                records.extend(value)
    missing = {"_id": 0, "_index": 0, "host.id": 0, "process.entity_id": 0, "event.code": 0}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        if not rec.get("_id"):
            missing["_id"] += 1
        if not rec.get("_index"):
            missing["_index"] += 1
        host = rec.get("host") or {}
        if not host.get("id"):
            missing["host.id"] += 1
        process = rec.get("process") or {}
        if not process.get("entity_id"):
            missing["process.entity_id"] += 1
        event = rec.get("event") or {}
        if not event.get("code"):
            missing["event.code"] += 1

    print(f"LEGACY (not replayable): {path} ({len(records)} records)")
    for field, count in missing.items():
        if count:
            print(f"  - {count}/{len(records)} records lack {field}")
    print(f"  declared: {meta.get('note', '')}")
    return 0

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("export")
    parser.add_argument("--allow-legacy", action="store_true")
    args = parser.parse_args()

    path = Path(args.export)
    if not path.is_file():
        print(f"missing export: {path}")
        return 2
    try:
        export = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"invalid json: {exc}")
        return 2

    # the schema file must exist; it is the contract this tool implements
    if not SCHEMA.is_file():
        print(f"schema contract missing: {SCHEMA}")
        return 2

    if 'schema' not in export:
        return legacy_report(path, export)

    errors = validate(export, args.allow_legacy)
    if errors:
        print(f"EVIDENCE INVALID: {path}")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"evidence valid: {path} ({len(export.get('records', []))} records, kind={export['capture']['capture_kind']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())


