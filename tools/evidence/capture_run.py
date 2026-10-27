#!/usr/bin/env python3
"""Capture a run into an evidence bundle.

Three parts, kept separate:

* **source documents** - the events each alert matched, resolved through `kibana.alert.ancestors`, with a
  per-alert status (`resolved`, `partial`, `unresolved`, `no_ancestors`);
* **context documents** - queries anchored on the alert's host and time (plus or minus a window), labelled
  with the query, the anchor, the returned count and whether the result was truncated;
* **metadata** - windows, stack, counts, and a manifest with checksums.

Nothing is synthesized. A locator that cannot be resolved is recorded, never replaced.

Usage:
    ES_URL=... ES_PASS=... python3 tools/evidence/capture_run.py --run-id run-1 \
        --start 2026-10-27T12:20:00Z --end 2026-10-27T12:40:00Z \
        --out evidence/runs/run-1 [--size 25] [--context-window 180]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import ssl
import sys
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

SYSMON = "logs-windows.sysmon_operational-*"
SECURITY = "logs-system.security-*"
ALERTS = ".internal.alerts-security.alerts-default*"
ALERT_PAGE = 500

SECRET_VALUE = re.compile(r"(Summer2026!|Zq7!Kernel-Lab-2026#x|Password123!|Helpdesk2026!|Welcome1!)")
SECRET_ARG = re.compile(r"(/(?:password|p)\s+)(\S+)", re.IGNORECASE)


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


def redact(value):
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        value = SECRET_ARG.sub(r"\1***", value)
        value = SECRET_VALUE.sub("***", value)
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
        data = self.call(f"/{index}/_search", body, "POST")
        failed = data.get("_shards", {}).get("failed", 0)
        if failed:
            failures = data.get("_shards", {}).get("failures", [])
            reason = failures[0].get("reason", {}).get("reason") if failures else "unknown"
            raise RuntimeError(f"shard failure on {index}: {reason}")
        return data

    def mget(self, groups: dict[str, list[str]]) -> list[dict]:
        resolved: list[dict] = []
        for index, ids in groups.items():
            for i in range(0, len(ids), 100):
                body = {"docs": [{"_index": index, "_id": doc_id} for doc_id in ids[i:i + 100]]}
                resolved.extend(doc for doc in self.call("/_mget", body, "POST").get("docs", []) if doc.get("found"))
        return resolved

    def all_alerts(self, start: str, end: str) -> tuple[list[dict], bool]:
        """Page through every alert in the window. Fails loudly on a shard error."""
        hits: list[dict] = []
        offset = 0
        while True:
            body = {"size": ALERT_PAGE, "from": offset, "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
                    "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": start, "lte": end}}}]}}}
            page = self.search(ALERTS, body).get("hits", {}).get("hits", [])
            hits.extend(page)
            if len(page) < ALERT_PAGE:
                return hits, False
            offset += ALERT_PAGE
            if offset >= 9000:
                return hits, True


def ancestors_of(document: dict) -> list[dict]:
    return get_field(document.get("_source", {}), "kibana.alert.ancestors", []) or []


def resolve_alert_sources(es: Elastic, alerts: list[dict], depth: int = 3) -> dict:
    """Resolve each alert's ancestors and record how far each one got."""
    per_alert: dict[str, list[dict]] = {}
    status: dict[str, dict] = {}
    unresolved: list[dict] = []
    cache: dict[tuple[str, str], dict | None] = {}

    def fetch(index: str, doc_id: str) -> dict | None:
        key = (index, doc_id)
        if key not in cache:
            docs = es.mget({index: [doc_id]})
            cache[key] = docs[0] if docs else None
        return cache[key]

    def walk(alert_id: str, items: list[dict], level: int, path: frozenset, state: dict) -> None:
        for item in items:
            index, doc_id = item.get("index"), item.get("id")
            if not index or not doc_id:
                unresolved.append({"alert": alert_id, "ancestor": item, "reason": "missing locator"})
                state["unresolved"] = True
                continue
            key = (index, doc_id)
            if key in path:
                unresolved.append({"alert": alert_id, "ancestor": item, "reason": "ancestor cycle"})
                state["unresolved"] = True
                continue
            doc = fetch(index, doc_id)
            if doc is None:
                unresolved.append({"alert": alert_id, "ancestor": item, "reason": "document not found"})
                state["unresolved"] = True
                continue
            source = doc.get("_source", {})
            is_alert = get_field(source, "kibana.alert.uuid") is not None
            per_alert.setdefault(alert_id, []).append({
                "_index": doc["_index"], "_id": doc["_id"], "_source": source,
                "kind": "alert" if is_alert else "event",
            })
            if is_alert:
                if level - 1 <= 0:
                    unresolved.append({"alert": alert_id, "ancestor": item, "reason": "depth_limit_reached"})
                    state["depth_limited"] = True
                    continue
                walk(alert_id, ancestors_of(doc), level - 1, path | {key}, state)
            else:
                state["event"] = True

    for alert in alerts:
        state = {"event": False, "unresolved": False, "depth_limited": False}
        items = ancestors_of(alert)
        if not items:
            status[alert["_id"]] = {"state": "no_ancestors", "events": 0}
            continue
        walk(alert["_id"], items, depth, frozenset(), state)
        events = len([d for d in per_alert.get(alert["_id"], []) if d["kind"] == "event"])
        if state["depth_limited"]:
            state_name = "partial"
        elif events == 0:
            state_name = "unresolved"
        elif state["unresolved"]:
            state_name = "partial"
        else:
            state_name = "resolved"
        status[alert["_id"]] = {"state": state_name, "events": events}

    return {"per_alert": per_alert, "unresolved": unresolved, "status": status}


CONTEXT_QUERIES = {
    "process_creation": (SYSMON, {"term": {"event.code": "1"}}),
    "module_load": (SYSMON, {"term": {"event.code": "7"}}),
    "remote_thread": (SYSMON, {"term": {"event.code": "8"}}),
    "lsass_access": (SYSMON, {"term": {"event.code": "10"}}),
    "file_creation": (SYSMON, {"term": {"event.code": "11"}}),
    "logon": (SECURITY, {"terms": {"event.code": ["4624", "4625"]}}),
}


def anchors_from(alerts: list[dict], status: dict) -> list[dict]:
    """One anchor per alert that reached an event: its host and that event's time."""
    anchors = []
    for alert in alerts:
        entry = status.get(alert["_id"], {})
        if entry.get("state") not in {"resolved", "partial"}:
            continue
        host = get_field(alert["_source"], "host.name") or get_field(alert["_source"], "kibana.alert.original_host.name")
        ts = get_field(alert["_source"], "kibana.alert.original_time") or alert.get("@timestamp")
        if host and ts:
            anchors.append({"alert": alert["_id"], "host": host, "time": ts})
    return anchors


def capture_context(es: Elastic, anchors: list[dict], window: int, size: int) -> dict:
    """One query per behaviour per host, spanning the alert times on that host."""
    hosts: dict[str, list[dict]] = {}
    for anchor in anchors:
        hosts.setdefault(anchor["host"], []).append(anchor)

    out: dict[str, dict] = {}
    for host, items in hosts.items():
        times = sorted(datetime.fromisoformat(a["time"].replace("Z", "+00:00")) for a in items)
        start = (times[0] - timedelta(seconds=window)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end = (times[-1] + timedelta(seconds=window)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        stamp = start[11:19].replace(":", "")
        for name, (index, term) in CONTEXT_QUERIES.items():
            query = {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": start, "lte": end}}},
                {"term": {"host.name": host}},
                term,
            ]}}
            data = es.search(index, {"size": size, "sort": [{"@timestamp": "asc"}], "query": query})
            hits = data.get("hits", {}).get("hits", [])
            total = data.get("hits", {}).get("total", {}).get("value", 0)
            key = f"{name}__{host}__{stamp}"
            out[key] = {
                "behaviour": name, "index": index, "query": query,
                "anchor": {"host": host, "alerts": len(items),
                           "first_alert": items[0]["alert"], "last_alert": items[-1]["alert"]},
                "window": {"start": start, "end": end},
                "returned": len(hits), "total": total, "truncated": len(hits) < total,
                "sample": len(hits) < total, "order": "ascending, first page of the window",
                "hits": hits,
            }
    return out


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
    parser.add_argument("--context-window", type=int, default=180)
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
    alerts, alerts_truncated = es.all_alerts(args.start, args.end)
    c0015 = [a for a in alerts if (get_field(a["_source"], "kibana.alert.rule.name", "") or "").startswith(args.rule_prefix)]
    other = [a for a in alerts if a not in c0015]

    resolved = resolve_alert_sources(es, c0015)
    anchors = anchors_from(c0015, resolved["status"])
    context = capture_context(es, anchors, args.context_window, args.size)

    write_json(out / "alerts" / "c0015.json", c0015)
    write_json(out / "alerts" / "other_rules.json", other)
    write_json(out / "sources" / "by_alert.json", resolved["per_alert"])
    write_json(out / "sources" / "status.json", resolved["status"])
    write_json(out / "sources" / "unresolved.json", resolved["unresolved"])
    for name, payload in context.items():
        write_json(out / "context" / f"{name}.json", payload)

    by_rule: dict[str, int] = {}
    for alert in c0015:
        rule_name = get_field(alert["_source"], "kibana.alert.rule.name", "unknown")
        by_rule[rule_name] = by_rule.get(rule_name, 0) + 1

    states: dict[str, int] = {}
    for entry in resolved["status"].values():
        states[entry["state"]] = states.get(entry["state"], 0) + 1

    meta = {
        "schema": "c0015.evidence.run/3",
        "run_id": args.run_id,
        "capture_id": capture_id,
        "captured_utc": datetime.now(timezone.utc).isoformat(),
        "stack": f"elasticsearch {es.version()}",
        "window": {"start": args.start, "end": args.end, "timezone": "UTC"},
        "alerts": {"c0015": len(c0015), "other": len(other), "by_rule": by_rule, "truncated": alerts_truncated},
        "sources": {
            "resolved_documents": sum(len(v) for v in resolved["per_alert"].values()),
            "alerts_with_source": len([s for s in resolved["status"].values() if s["events"] > 0]),
            "states": states,
            "unresolved": len(resolved["unresolved"]),
        },
        "context": {name: {"behaviour": c["behaviour"], "anchor": c["anchor"], "window": c["window"],
                           "returned": c["returned"], "total": c["total"], "truncated": c["truncated"]}
                    for name, c in context.items()},
        "query_size": args.size,
        "context_window_seconds": args.context_window,
    }
    write_json(out / "run.json", meta)

    manifest = {"schema": "c0015.evidence.manifest/2", "capture_id": capture_id, "files": []}
    for path in sorted(out.rglob("*.json")):
        if path.name == "manifest.json":
            continue
        manifest["files"].append({"path": str(path.relative_to(out)).replace("\\", "/"),
                                  "sha256": sha256_file(path), "bytes": path.stat().st_size})
    write_json(out / "manifest.json", manifest)

    print(json.dumps({"alerts_c0015": len(c0015), "other": len(other),
                      "source_documents": meta["sources"]["resolved_documents"],
                      "states": states, "unresolved": meta["sources"]["unresolved"],
                      "context_buckets": len(context)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
