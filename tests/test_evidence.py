#!/usr/bin/env python3
"""Offline tests for the evidence tooling. No Elasticsearch, no network.

Run with: python3 tests/test_evidence.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "evidence"))

import capture_run  # noqa: E402
import validate_run  # noqa: E402

failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"ok   {name}")
    else:
        failures.append(f"{name}: {detail}")
        print(f"FAIL {name} {detail}")


# --- get_field -------------------------------------------------------------------------------
dotted = {"kibana.alert.ancestors": [{"index": "a", "id": "1"}], "kibana.alert.rule.name": "C0015 | x"}
nested = {"kibana": {"alert": {"ancestors": [{"index": "b", "id": "2"}], "rule": {"name": "C0015 | y"}}}}
check("dotted ancestors", capture_run.get_field(dotted, "kibana.alert.ancestors") == [{"index": "a", "id": "1"}])
check("nested ancestors", capture_run.get_field(nested, "kibana.alert.ancestors") == [{"index": "b", "id": "2"}])
check("dotted rule name", capture_run.get_field(dotted, "kibana.alert.rule.name") == "C0015 | x")
check("missing field returns default", capture_run.get_field({}, "kibana.alert.ancestors", []) == [])
check("non-dict input", capture_run.get_field(None, "a.b", "x") == "x")


# --- ancestor resolution ---------------------------------------------------------------------
class StubElastic:
    def __init__(self, documents: dict[tuple[str, str], dict]) -> None:
        self.documents = documents
        self.calls: list[tuple[str, str]] = []

    def mget(self, groups: dict[str, list[str]]) -> list[dict]:
        out = []
        for index, ids in groups.items():
            for doc_id in ids:
                self.calls.append((index, doc_id))
                doc = self.documents.get((index, doc_id))
                if doc:
                    out.append({"_index": index, "_id": doc_id, "_source": doc})
        return out


event = {"event": {"code": "1"}}
nested_alert = {"kibana.alert.uuid": "parent-alert", "kibana.alert.ancestors": [{"index": "idx", "id": "e2"}]}

alerts = [
    {"_id": "alert-1", "_source": {"kibana.alert.ancestors": [{"index": "idx", "id": "e1"}]}},
    {"_id": "alert-2", "_source": {"kibana.alert.ancestors": [{"index": "idx", "id": "e1"}]}},
    {"_id": "alert-3", "_source": {"kibana.alert.ancestors": [{"index": "idx", "id": "missing"}]}},
    {"_id": "alert-4", "_source": {"kibana.alert.ancestors": [{"index": "idx", "id": "a1"}]}},
]
stub = StubElastic({("idx", "e1"): event, ("idx", "a1"): nested_alert, ("idx", "e2"): event})
resolved = capture_run.resolve_alert_sources(stub, alerts)

check("two alerts share one source", len(resolved["per_alert"]["alert-1"]) == 1 and len(resolved["per_alert"]["alert-2"]) == 1)
check("shared source fetched once", stub.calls.count(("idx", "e1")) == 1)
check("missing document is unresolved", any(u["alert"] == "alert-3" for u in resolved["unresolved"]))
check("alert ancestor is followed",
      [d["kind"] for d in resolved["per_alert"]["alert-4"]] == ["alert", "event"])
check("alert ancestor label", resolved["per_alert"]["alert-4"][0]["_source"]["kibana.alert.uuid"] == "parent-alert")


# --- bundle validator ------------------------------------------------------------------------
with tempfile.TemporaryDirectory() as tmp:
    bundle = Path(tmp)
    (bundle / "alerts").mkdir()
    (bundle / "sources").mkdir()
    (bundle / "context").mkdir()
    alerts_out = [{"_id": "alert-1", "_source": {}}]
    (bundle / "alerts" / "c0015.json").write_text(json.dumps(alerts_out), encoding="utf-8")
    (bundle / "sources" / "by_alert.json").write_text(json.dumps({"alert-1": [{"_index": "i", "_id": "e"}]}), encoding="utf-8")
    (bundle / "sources" / "unresolved.json").write_text("[]", encoding="utf-8")
    (bundle / "context" / "process_creation.json").write_text(
        json.dumps({"returned": 0, "total": 0, "truncated": False, "sample": False, "hits": []}), encoding="utf-8")
    run = {"schema": "c0015.evidence.run/2", "capture_id": "cap-1",
           "window": {"start": "2026-10-27T00:00:00Z", "end": "2026-10-27T01:00:00Z"},
           "alerts": {"c0015": 1, "other": 0}, "sources": {"alerts_with_source": 1},
           "context": {"process_creation": {"returned": 0, "total": 0, "truncated": False}}}
    (bundle / "run.json").write_text(json.dumps(run), encoding="utf-8")
    manifest = {"schema": "c0015.evidence.manifest/1",
                "files": [{"path": str(p.relative_to(bundle)).replace("\\", "/"),
                           "sha256": validate_run.sha256_file(p)} for p in bundle.rglob("*.json") if p.name != "manifest.json"]}
    (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    check("valid bundle passes", validate_run.validate(bundle) == [], str(validate_run.validate(bundle)))

    (bundle / "alerts" / "c0015.json").write_text(json.dumps([{"_id": "alert-9", "_source": {}}]), encoding="utf-8")
    errors = validate_run.validate(bundle)
    check("unlinked alert fails", any("neither a source document" in e for e in errors), str(errors))

with tempfile.TemporaryDirectory() as tmp:
    bundle = Path(tmp)
    (bundle / "alerts").mkdir()
    (bundle / "sources").mkdir()
    (bundle / "alerts" / "c0015.json").write_text(json.dumps([{"_id": "a"}]), encoding="utf-8")
    (bundle / "sources" / "by_alert.json").write_text("{}", encoding="utf-8")
    (bundle / "sources" / "unresolved.json").write_text(json.dumps([{"alert": "a", "reason": "x"}]), encoding="utf-8")
    (bundle / "run.json").write_text(json.dumps({"schema": "c0015.evidence.run/2", "capture_id": "c",
                                                 "window": {"start": "2026-10-27T00:00:00Z", "end": "2026-10-27T01:00:00Z"},
                                                 "alerts": {"c0015": 1}, "sources": {"alerts_with_source": 0}, "context": {}}),
                                     encoding="utf-8")
    (bundle / "manifest.json").write_text(json.dumps({"files": []}), encoding="utf-8")
    errors = validate_run.validate(bundle)
    check("unresolved alert is allowed", not any("neither a source" in e for e in errors), str(errors))
    check("manifest mismatch fails", any("not covered by the manifest" in e for e in errors), str(errors))

print()
if failures:
    print(f"FAILED ({len(failures)})")
    for failure in failures:
        print(" -", failure)
    sys.exit(1)
print("all evidence tests passed")
