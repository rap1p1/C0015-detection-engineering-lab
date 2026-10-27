#!/usr/bin/env python3
"""Capture a run into an evidence bundle.

The bundle keeps three things separate:

* **source documents** - the events the alerts actually matched, resolved through `kibana.alert.ancestors`;
* **context documents** - wider queries around the same window, each labelled with the query that produced
  it and whether the result was complete or a sample;
* **metadata** - windows, stack, counts, unresolved locators, and a manifest with checksums.

Nothing is synthesized. A locator that cannot be resolved is recorded as unresolved, never replaced.

Usage:
    ES_URL=... ES_PASS=... python3 tools/evidence/capture_run.py \
        --run-id run-1 \
        --start 2026-10-27T12:20:00Z --end 2026-10-27T12:40:00Z \
        --out evidence/runs/run-1 [--size 25] [--rule-prefix "C0015 |"]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import json
import os
import ssl
import sys
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

SYSMON = "logs-windows.sysmon_operational-*"
SECURITY = "logs-system.security-*"
ALERTS = ".internal.alerts-security.alerts-default*"


def get_field(document, path, default=None):
    """Read a field stored either as a dotted key or as nested objects."""
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


class Elastic:
    def __init__(self, url: str, user: str, password: str) -> None:
        self.url = url.rstrip("/")
        self.auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.ctx = ssl._create_unverified_context()

    def call(self, path: str, body: dict | None = None, method: str = "GET") -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.url + path, data=data, method=method,
            headers={"Authorization": "Basic " + self.auth, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=120, context=self.ctx) as response:
            return json.load(response)

    def version(self) -> str:
        return self.call("/")["version"]["number"]

    def search(self, index: str, body: dict) -> dict:
        return self.call(f"/{index}/_search", body, "POST")

    def mget(self, groups: dict[str, list[str]]) -> list[dict]:
        resolved: list[dict] = []
        for index, ids in groups.items():
            for i in range(0, len(ids), 100):
                body = {"docs": [{"_index": index, "_id": doc_id} for doc_id in ids[i:i + 100]]}
                resolved.extend(doc for doc in self.call("/_mget", body, "POST").get("docs", []) if doc.get("found"))
        return resolved


def ancestors_of(document: dict) -> list[dict]:
    return get_field(document.get("_source", {}), "kibana.alert.ancestors", []) or []


def resolve_alert_sources(es: Elastic, alerts: list[dict], depth: int = 3) -> dict:
    """Resolve every alert's ancestors. Each alert keeps its own links; documents are fetched once."""
    per_alert: dict[str, list[dict]] = {}
    unresolved: list[dict] = []
    cache: dict[tuple[str, str], dict | None] = {}

    def fetch(index: str, doc_id: str) -> dict | None:
        key = (index, doc_id)
        if key not in cache:
            docs = es.mget({index: [doc_id]})
            cache[key] = docs[0] if docs else None
        return cache[key]

    def walk(alert_id: str, items: list[dict], level: int, path: frozenset) -> None:
        if level <= 0:
            return
        for item in items:
            index, doc_id = item.get("index"), item.get("id")
            if not index or not doc_id:
                unresolved.append({"alert": alert_id, "ancestor": item, "reason": "missing locator"})
                continue
            key = (index, doc_id)
            if key in path:
                unresolved.append({"alert": alert_id, "ancestor": item, "reason": "ancestor cycle"})
                continue
            doc = fetch(index, doc_id)
            if doc is None:
                unresolved.append({"alert": alert_id, "ancestor": item, "reason": "document not found"})
                continue
            source = doc.get("_source", {})
            is_alert = get_field(source, "kibana.alert.uuid") is not None
            per_alert.setdefault(alert_id, []).append({
                "_index": doc["_index"], "_id": doc["_id"], "_source": source,
                "kind": "alert" if is_alert else "event",
            })
            if is_alert:
                walk(alert_id, ancestors_of(doc), level - 1, path | {key})

    for alert in alerts:
        walk(alert["_id"], ancestors_of(alert), depth, frozenset())
    return {"per_alert": per_alert, "unresolved": unresolved}


CONTEXT_QUERIES = {
    "process_creation": (SYSMON, {"term": {"event.code": "1"}}),
    "module_load": (SYSMON, {"term": {"event.code": "7"}}),
    "remote_thread": (SYSMON, {"term": {"event.code": "8"}}),
    "lsass_access": (SYSMON, {"term": {"event.code": "10"}}),
    "file_creation": (SYSMON, {"term": {"event.code": "11"}}),
    "logon": (SECURITY, {"terms": {"event.code": ["4624", "4625"]}}),
}


def capture_context(es: Elastic, start: str, end: str, size: int) -> dict:
    out = {}
    for name, (index, term) in CONTEXT_QUERIES.items():
        query = {"bool": {"filter": [{"range": {"@timestamp": {"gte": start, "lte": end}}}, term]}}
        data = es.search(index, {"size": size, "sort": [{"@timestamp": "asc"}], "query": query})
        hits = data.get("hits", {}).get("hits", [])
        total = data.get("hits", {}).get("total", {}).get("value", 0)
        out[name] = {"index": index, "query": query, "returned": len(hits), "total": total,
                     "truncated": len(hits) < total, "sample": len(hits) < total, "hits": hits}
    return out


SECRET_VALUE = re.compile(r"(Summer2026!|Zq7!Kernel-Lab-2026#x|Password123!|Helpdesk2026!|Welcome1!)")
SECRET_ARG = re.compile(r"(/(?:password|p)\s+)(\S+)", re.IGNORECASE)


def redact(value):
    """Remove lab credentials from anything written into the public bundle."""
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        value = SECRET_ARG.sub(r"\1***", value)
        value = SECRET_VALUE.sub("***", value)
    return value


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(redact(payload), indent=2), encoding="utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--start", required=True)
    parser.add_argument("--end", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--size", type=int, default=25)
    parser.add_argument("--rule-prefix", default="C0015 |")
    parser.add_argument("--capture-id", default=None)
    args = parser.parse_args()

    password = os.environ.get("ES_PASS")
    if not password:
        print("ES_PASS is not set")
        return 2
    es = Elastic(os.environ.get("ES_URL", "https://localhost:9200"),
                 os.environ.get("ES_USER", "elastic"), password)

    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        print(f"refusing to overwrite a non-empty bundle: {out}")
        return 2

    capture_id = args.capture_id or f"cap-{uuid.uuid4().hex[:12]}"
    window = {"range": {"@timestamp": {"gte": args.start, "lte": args.end}}}
    alerts = es.search(ALERTS, {"size": 500, "sort": [{"@timestamp": "asc"}],
                                "query": {"bool": {"filter": [window]}}}).get("hits", {}).get("hits", [])
    c0015 = [a for a in alerts if (get_field(a["_source"], "kibana.alert.rule.name", "") or "").startswith(args.rule_prefix)]
    other = [a for a in alerts if a not in c0015]

    resolved = resolve_alert_sources(es, c0015)
    context = capture_context(es, args.start, args.end, args.size)

    write_json(out / "alerts" / "c0015.json", c0015)
    write_json(out / "alerts" / "other_rules.json", other)
    write_json(out / "sources" / "by_alert.json", resolved["per_alert"])
    write_json(out / "sources" / "unresolved.json", resolved["unresolved"])
    for name, payload in context.items():
        write_json(out / "context" / f"{name}.json", payload)

    by_rule: dict[str, int] = {}
    for alert in c0015:
        name = get_field(alert["_source"], "kibana.alert.rule.name", "unknown")
        by_rule[name] = by_rule.get(name, 0) + 1

    meta = {
        "schema": "c0015.evidence.run/2",
        "run_id": args.run_id,
        "capture_id": capture_id,
        "captured_utc": datetime.now(timezone.utc).isoformat(),
        "stack": f"elasticsearch {es.version()}",
        "window": {"start": args.start, "end": args.end, "timezone": "UTC"},
        "alerts": {"c0015": len(c0015), "other": len(other), "by_rule": by_rule},
        "sources": {
            "resolved_documents": sum(len(v) for v in resolved["per_alert"].values()),
            "alerts_with_source": len([v for v in resolved["per_alert"].values() if v]),
            "unresolved": len(resolved["unresolved"]),
        },
        "context": {name: {"returned": c["returned"], "total": c["total"], "truncated": c["truncated"]}
                    for name, c in context.items()},
        "query_size": args.size,
    }
    write_json(out / "run.json", meta)

    manifest = {"schema": "c0015.evidence.manifest/1", "capture_id": capture_id, "files": []}
    for path in sorted(out.rglob("*.json")):
        if path.name == "manifest.json":
            continue
        manifest["files"].append({"path": str(path.relative_to(out)).replace("\\", "/"),
                                  "sha256": sha256_file(path), "bytes": path.stat().st_size})
    write_json(out / "manifest.json", manifest)

    print(json.dumps({"alerts_c0015": len(c0015), "other": len(other),
                      "source_documents": meta["sources"]["resolved_documents"],
                      "alerts_with_source": meta["sources"]["alerts_with_source"],
                      "unresolved": meta["sources"]["unresolved"],
                      "context": meta["context"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

