#!/usr/bin/env python3
"""Validate an evidence bundle produced by capture_run.py.

The checks are structural and relational: every file is in the manifest, every count matches the data,
every linked document is reachable from the alert it is linked to, and every context hit belongs to the
identifier, host and query window the record declares.

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


def ancestors_of(document: dict) -> list[dict]:
    source = document.get("_source", document)
    return field(source, "kibana.alert.ancestors", None) or []


def reachable(alert: dict, linked: list[dict]) -> set[tuple[str, str]]:
    """Locators reachable from the alert by following ancestors through linked alert documents."""
    seen: set[tuple[str, str]] = set()
    frontier = [(item.get("index"), item.get("id")) for item in ancestors_of(alert)]
    by_locator = {(doc["_index"], doc["_id"]): doc for doc in linked}
    while frontier:
        locator = frontier.pop()
        if locator in seen:
            continue
        seen.add(locator)
        doc = by_locator.get(locator)
        if doc and doc.get("kind") == "alert":
            frontier.extend((item.get("index"), item.get("id")) for item in ancestors_of(doc))
    return seen


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

    recomputed_states: dict[str, int] = {}
    for alert in alerts:
        alert_id = alert.get("_id")
        state = status.get(alert_id, {}).get("state")
        linked = sources.get(alert_id, [])
        events = [doc for doc in linked if doc.get("kind") == "event"]
        reach = reachable(alert, linked)

        if len(events) != status.get(alert_id, {}).get("events", 0):
            errors.append(f"{alert_id}: status.events does not match the linked event count")
        own_unresolved = [item for item in unresolved if item.get("alert") == alert_id]
        reasons = {item.get("reason") for item in own_unresolved}
        if not ancestors_of(alert) and not linked:
            expected_state = "no_ancestors"
        elif not events:
            expected_state = "unresolved"
        elif reasons - {"depth_limit_reached"}:
            expected_state = "partial"
        elif "depth_limit_reached" in reasons:
            expected_state = "partial"
        else:
            expected_state = "resolved"
        if state != expected_state:
            errors.append(f"{alert_id}: state {state!r} but the graph implies {expected_state!r}")
        recomputed_states[expected_state] = recomputed_states.get(expected_state, 0) + 1

        if state in {"resolved", "partial"} and not events:
            errors.append(f"{alert_id}: state {state} but no event document linked")
        if state == "no_ancestors" and linked:
            errors.append(f"{alert_id}: no_ancestors but documents linked")
        if state == "resolved" and any(item.get("alert") == alert_id for item in unresolved):
            errors.append(f"{alert_id}: state resolved but listed as unresolved")

        for doc in linked:
            locator = (doc.get("_index"), doc.get("_id"))
            if locator not in reach:
                errors.append(f"{alert_id}: linked document {locator[1]} is not on the alert's ancestor path")
        if state == "resolved" and events:
            if not any((doc["_index"], doc["_id"]) in reach for doc in events):
                errors.append(f"{alert_id}: resolved event is not on the alert's ancestor path")

    declared_states = field(run, "sources.states") or {}
    for name, count in declared_states.items():
        if recomputed_states.get(name, 0) != count:
            errors.append(f"run.json states[{name}] is {count}, recomputed {recomputed_states.get(name, 0)}")
    for name, count in recomputed_states.items():
        if name not in declared_states:
            errors.append(f"run.json states is missing {name} ({count})")

    with_source = len([s for s in status.values() if s.get("events", 0) > 0])
    if field(run, "sources.alerts_with_source") != with_source:
        errors.append("run.json alerts_with_source does not match sources/status.json")
    if field(run, "sources.unresolved") != len(unresolved):
        errors.append("run.json unresolved count does not match sources/unresolved.json")

    for name, info in (field(run, "context") or {}).items():
        payload = load(f"context/{name}.json", None)
        if payload is None:
            errors.append(f"context file missing: {name}")
            continue
        hits = payload.get("hits", [])
        if payload.get("returned") != len(hits):
            errors.append(f"context {name}: returned does not match hits")
        if info.get("returned") != payload.get("returned"):
            errors.append(f"context {name}: run.json count disagrees with the file")

        identifier = payload.get("identifier", {})
        host = identifier.get("host")
        value = identifier.get("value")
        id_field = identifier.get("field")
        for hit in hits:
            if hit.get("query_index") is None or not (0 <= hit["query_index"] < len(payload.get("queries", []))):
                errors.append(f"context {name}: hit without a valid query index")
                continue
            query = payload["queries"][hit["query_index"]]
            window = query.get("window", {})
            ts = parse_ts(field(hit["_source"], "@timestamp"))
            w_start, w_end = parse_ts(window.get("start")), parse_ts(window.get("end"))
            if not ts or not w_start or not w_end or not (w_start <= ts <= w_end):
                errors.append(f"context {name}: hit timestamp outside its query window")
            if field(hit["_source"], "host.name") != host:
                errors.append(f"context {name}: hit host does not match the identifier host")
            if id_field and value:
                candidates = identifier.get("fields") or [id_field]
                if not any(field(hit["_source"], candidate) == value for candidate in candidates):
                    errors.append(f"context {name}: hit does not carry the declared identifier")

        truncated = any((q.get("returned", 0) < (q.get("total") or 0)) for q in payload.get("queries", []))
        if payload.get("truncated") != truncated:
            errors.append(f"context {name}: truncated flag does not match its queries")

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
