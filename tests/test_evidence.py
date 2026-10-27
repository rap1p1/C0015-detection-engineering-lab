#!/usr/bin/env python3
"""Offline tests for the evidence tooling. No Elasticsearch, no network.

Run with: python3 tests/test_evidence.py
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "evidence"))

import capture_run  # noqa: E402
import validate_run  # noqa: E402

failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    print(("ok   " if condition else "FAIL ") + name + ("" if condition else f" {detail}"))
    if not condition:
        failures.append(name)


# --- get_field -------------------------------------------------------------------------------
dotted = {"kibana.alert.ancestors": [{"index": "a", "id": "1"}], "kibana.alert.rule.name": "C0015 | x"}
nested = {"kibana": {"alert": {"ancestors": [{"index": "b", "id": "2"}], "rule": {"name": "C0015 | y"}}}}
check("dotted ancestors", capture_run.get_field(dotted, "kibana.alert.ancestors") == [{"index": "a", "id": "1"}])
check("nested ancestors", capture_run.get_field(nested, "kibana.alert.ancestors") == [{"index": "b", "id": "2"}])
check("dotted rule name", capture_run.get_field(dotted, "kibana.alert.rule.name") == "C0015 | x")
check("missing returns default", capture_run.get_field({}, "kibana.alert.ancestors", []) == [])


# --- resolver --------------------------------------------------------------------------------
class StubElastic:
    def __init__(self, documents):
        self.documents = documents
        self.calls = []

    def mget(self, groups):
        out = []
        for index, ids in groups.items():
            for doc_id in ids:
                self.calls.append((index, doc_id))
                doc = self.documents.get((index, doc_id))
                if doc:
                    out.append({"_index": index, "_id": doc_id, "_source": doc})
        return out


def alert_doc(ancestors):
    return {"kibana.alert.uuid": "inner", "kibana.alert.ancestors": ancestors}


event = {"event": {"code": "1"}}
alerts = [
    {"_id": "a1", "_source": {"kibana.alert.ancestors": [{"index": "i", "id": "e1"}]}},
    {"_id": "a2", "_source": {"kibana.alert.ancestors": [{"index": "i", "id": "e1"}]}},
    {"_id": "a3", "_source": {"kibana.alert.ancestors": [{"index": "i", "id": "gone"}]}},
    {"_id": "a4", "_source": {"kibana.alert.ancestors": [{"index": "i", "id": "in1"}]}},
    {"_id": "a5", "_source": {}},
    {"_id": "a6", "_source": {"kibana.alert.ancestors": [{"index": "i", "id": "d1"}]}},
]
stub = StubElastic({
    ("i", "e1"): event,
    ("i", "in1"): alert_doc([{"index": "i", "id": "e2"}]),
    ("i", "e2"): event,
    ("i", "d1"): alert_doc([{"index": "i", "id": "d2"}]),
    ("i", "d2"): alert_doc([{"index": "i", "id": "d3"}]),
    ("i", "d3"): alert_doc([{"index": "i", "id": "d4"}]),
})
res = capture_run.resolve_alert_sources(stub, alerts, depth=2)

check("shared source linked to both alerts",
      len(res["per_alert"]["a1"]) == 1 and len(res["per_alert"]["a2"]) == 1)
check("shared source fetched once", stub.calls.count(("i", "e1")) == 1)
check("missing document unresolved", any(u["alert"] == "a3" for u in res["unresolved"]))
check("alert ancestor followed", [d["kind"] for d in res["per_alert"]["a4"]] == ["alert", "event"])
check("no ancestors state", res["status"]["a5"]["state"] == "no_ancestors")
check("depth limit reported", any(u.get("reason") == "depth_limit_reached" for u in res["unresolved"]))
check("depth limited alert is partial", res["status"]["a6"]["state"] == "partial")


# --- bundle fixture helpers ------------------------------------------------------------------
def write_bundle(root: Path, *, source_id: str = "e1", hits_count: int = 2,
                 returned: int | None = None, docs_stat: int | None = None) -> Path:
    (root / "alerts").mkdir(parents=True)
    (root / "sources").mkdir()
    (root / "context").mkdir()
    alert = {"_id": "a1", "_source": {"kibana.alert.rule.name": "C0015 | x",
                                      "kibana.alert.ancestors": [{"index": "i", "id": "e1"}]}}
    (root / "alerts" / "c0015.json").write_text(json.dumps([alert]), encoding="utf-8")
    (root / "alerts" / "other_rules.json").write_text("[]", encoding="utf-8")
    (root / "sources" / "by_alert.json").write_text(
        json.dumps({"a1": [{"_index": "i", "_id": source_id, "kind": "event"}]}), encoding="utf-8")
    (root / "sources" / "status.json").write_text(json.dumps({"a1": {"state": "resolved", "events": 1}}), encoding="utf-8")
    (root / "sources" / "unresolved.json").write_text("[]", encoding="utf-8")
    hits = [{"_index": "i", "_id": f"c{n}"} for n in range(hits_count)]
    (root / "context" / "process_creation__h__t.json").write_text(json.dumps(
        {"returned": returned if returned is not None else hits_count, "total": 10,
         "truncated": True, "hits": hits}), encoding="utf-8")
    run = {"schema": "c0015.evidence.run/3", "capture_id": "cap-1",
           "window": {"start": "2026-10-27T00:00:00Z", "end": "2026-10-27T01:00:00Z"},
           "alerts": {"c0015": 1, "other": 0, "by_rule": {"C0015 | x": 1}},
           "sources": {"resolved_documents": docs_stat if docs_stat is not None else 1,
                       "alerts_with_source": 1, "states": {"resolved": 1}, "unresolved": 0},
           "context": {"process_creation__h__t": {"returned": returned if returned is not None else hits_count,
                                                  "total": 10, "truncated": True}}}
    (root / "run.json").write_text(json.dumps(run), encoding="utf-8")
    manifest = {"schema": "c0015.evidence.manifest/2", "capture_id": "cap-1", "files": []}
    for path in root.rglob("*.json"):
        if path.name == "manifest.json":
            continue
        manifest["files"].append({"path": str(path.relative_to(root)).replace("\\", "/"),
                                  "sha256": validate_run.sha256_file(path)})
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return root


with tempfile.TemporaryDirectory() as tmp:
    bundle = write_bundle(Path(tmp) / "ok")
    check("valid bundle passes", validate_run.validate(bundle) == [], str(validate_run.validate(bundle)))

with tempfile.TemporaryDirectory() as tmp:
    bundle = write_bundle(Path(tmp) / "tamper-locator", source_id="not-an-ancestor")
    errors = validate_run.validate(bundle)
    check("source not in ancestors fails", any("ancestor path" in e for e in errors), str(errors))

with tempfile.TemporaryDirectory() as tmp:
    bundle = write_bundle(Path(tmp) / "tamper-hits", hits_count=0, returned=2)
    errors = validate_run.validate(bundle)
    check("returned vs hits mismatch fails", any("returned does not match hits" in e for e in errors), str(errors))

with tempfile.TemporaryDirectory() as tmp:
    bundle = write_bundle(Path(tmp) / "tamper-stats", docs_stat=9)
    errors = validate_run.validate(bundle)
    check("source statistics mismatch fails", any("resolved_documents" in e for e in errors), str(errors))

with tempfile.TemporaryDirectory() as tmp:
    bundle = write_bundle(Path(tmp) / "tamper-capture")
    run = json.loads((bundle / "run.json").read_text(encoding="utf-8"))
    run["capture_id"] = "cap-2"
    (bundle / "run.json").write_text(json.dumps(run), encoding="utf-8")
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        if entry["path"] == "run.json":
            entry["sha256"] = validate_run.sha256_file(bundle / "run.json")
    (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    errors = validate_run.validate(bundle)
    check("capture id mismatch fails", any("capture_id does not match" in e for e in errors), str(errors))

with tempfile.TemporaryDirectory() as tmp:
    bundle = write_bundle(Path(tmp) / "tamper-manifest")
    (bundle / "context" / "extra.json").write_text("{}", encoding="utf-8")
    errors = validate_run.validate(bundle)
    check("unlisted file fails", any("not covered by the manifest" in e for e in errors), str(errors))


with tempfile.TemporaryDirectory() as tmp:
    bundle = write_bundle(Path(tmp) / "nested")
    alert = {"_id": "a1", "_source": {"kibana.alert.rule.name": "C0015 | x",
                                      "kibana.alert.ancestors": [{"index": "i", "id": "inner-alert"}]}}
    (bundle / "alerts" / "c0015.json").write_text(json.dumps([alert]), encoding="utf-8")
    (bundle / "sources" / "by_alert.json").write_text(json.dumps({"a1": [
        {"_index": "i", "_id": "inner-alert", "kind": "alert",
         "_source": {"kibana.alert.uuid": "u", "kibana.alert.ancestors": [{"index": "i", "id": "e1"}]}},
        {"_index": "i", "_id": "e1", "kind": "event", "_source": {}}]}), encoding="utf-8")
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        target = bundle / entry["path"]
        entry["sha256"] = validate_run.sha256_file(target)
    (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    errors = validate_run.validate(bundle)
    check("event behind an alert ancestor is accepted",
          not any("ancestor path" in e for e in errors), str(errors))

print()
if failures:
    print(f"FAILED ({len(failures)})")
    for failure in failures:
        print(" -", failure)
    sys.exit(1)
print("all evidence tests passed")
