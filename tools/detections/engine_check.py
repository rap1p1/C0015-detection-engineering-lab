#!/usr/bin/env python3
"""Run every shipped rule against a live Elasticsearch and record the result in the catalog.

This is the engine layer of validation. It proves that the query parses and that the fields it names
exist in this pipeline; it does not prove that a match is a true positive, and it does not prove that a
scheduled detection alerts. Those are separate layers and are reported separately.

Usage:
    ES_URL=https://localhost:9200 ES_USER=elastic ES_PASS=... \
        python3 tools/detections/engine_check.py --window-start 2026-09-12T00:00:00Z \
        --write-catalog

Without --write-catalog the results are printed only. The script refuses to run when ES_PASS is unset,
so it can never run in CI by accident.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "detections" / "catalog.json"


def search(url: str, auth: str, index: str, body: dict) -> dict:
    req = urllib.request.Request(
        f"{url}/{index}/_eql/search",
        data=json.dumps(body).encode(),
        headers={"Authorization": "Basic " + auth, "Content-Type": "application/json"},
        method="POST",
    )
    ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=90, context=ctx) as response:
        return json.load(response)


def stack_version(url: str, auth: str) -> str:
    req = urllib.request.Request(url, headers={"Authorization": "Basic " + auth})
    ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
        return json.load(response)["version"]["number"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--window-start", required=True)
    parser.add_argument("--window-end", default="now")
    parser.add_argument("--write-catalog", action="store_true")
    parser.add_argument("--size", type=int, default=100)
    args = parser.parse_args()

    url = os.environ.get("ES_URL", "https://localhost:9200")
    user = os.environ.get("ES_USER", "elastic")
    password = os.environ.get("ES_PASS")
    if not password:
        print("ES_PASS is not set; refusing to run (this is the opt-in gate)")
        return 2
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()

    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    version = stack_version(url, auth)
    print(f"stack {version}")

    results = {}
    for rule in catalog["rules"]:
        if rule.get("status") != "shipped":
            continue
        query = (ROOT / rule["file"]).read_text(encoding="utf-8")
        index = ",".join(rule["deployment"]["index"])
        body = {"query": query, "size": args.size,
                "filter": {"range": {"@timestamp": {"gte": args.window_start, "lte": args.window_end}}}}
        rid = rule["id"]
        try:
            data = search(url, auth, index, body)
            hits = data.get("hits", {}).get("total", {}).get("value", 0)
            truncated = hits >= args.size
            results[rid] = {"matches": hits, "error": None, "truncated": truncated}
            print(f"{rid:12} matches={hits}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode()[:200]
            results[rid] = {"matches": None, "error": detail}
            print(f"{rid:12} ERROR {detail[:120]}")
        except Exception as exc:  # noqa: BLE001 - report, do not crash the run
            results[rid] = {"matches": None, "error": str(exc)}
            print(f"{rid:12} ERROR {exc}")

    errors = [rid for rid, res in results.items() if res["error"]]
    if errors:
        print(f"engine errors: {', '.join(errors)}")

    if args.write_catalog:
        for rule in catalog["rules"]:
            if rule["id"] not in results:
                continue
            res = results[rule["id"]]
            rule["validation"] = {
                "kind": "engine_run" if res["error"] is None else "engine_error",
                "engine": f"elasticsearch {version}",
                "window": {"start": args.window_start, "end": args.window_end},
                "matches": res["matches"],
                "truncated": res.get("truncated", False),
                "error": res["error"],
                "note": "Query parse and field existence only; matches are not classified as true or false positives.",
            }
        CATALOG.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
        print("catalog validation updated")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

