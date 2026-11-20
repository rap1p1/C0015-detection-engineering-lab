#!/usr/bin/env python3
"""Build and apply the Kibana rule bundle for the catalog.

Two modes so the same script runs locally (build) and on the Kibana host (apply):

    python3 tools/detections/kibana_bundle.py bundle --out bundle.json
    python3 tools/detections/kibana_bundle.py apply  --bundle bundle.json

`apply` never deploys anything on its own: it is a deliberate operator step, it requires the Kibana
password in the environment, and it only touches rules whose id starts with `c0015-`. Rules that are no
longer shipped are disabled and deleted, which is how a retired rule leaves the stack.
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

PREFIX = "c0015-"

def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def build(out: Path) -> int:
    root = repo_root()
    catalog = json.loads((root / "detections" / "catalog.json").read_text(encoding="utf-8"))
    bundle = []
    for rule in catalog["rules"]:
        if rule.get("status") != "shipped":
            continue
        query = (root / rule["file"]).read_text(encoding="utf-8")
        dep = rule["deployment"]
        bundle.append({
            "rule_id": PREFIX + rule["id"].split("-")[-1].lower(),
            "name": "C0015 | " + rule["name"],
            "description": rule["description"],
            "severity": rule["severity"],
            "risk_score": rule["risk_score"],
            "query": query,
            "index": dep["index"],
            "interval": dep["interval"],
            "from": dep["lookback"],
            "max_signals": dep["max_signals"],
            "enabled": dep["enabled"],
            "role": rule["role"],
            "threat": [{
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": rule["attck"]["tactic_id"],
                    "name": rule["attck"]["tactic_name"],
                    "reference": "https://attack.mitre.org/tactics/" + rule["attck"]["tactic_id"] + "/",
                },
                "technique": [{
                    "id": rule["attck"]["technique_id"],
                    "name": rule["attck"]["technique_name"],
                    "reference": "https://attack.mitre.org/techniques/" + rule["attck"]["technique_id"].replace(".", "/") + "/",
                }],
            }],
        })
    out.write_text(json.dumps({"rules": bundle}, indent=2), encoding="utf-8")
    print(f"bundle written: {out} ({len(bundle)} rules)")
    return 0


def apply(bundle_path: Path) -> int:
    password = os.environ.get("KIBANA_PASS")
    if not password:
        print("KIBANA_PASS is not set; refusing to apply")
        return 2
    kib = os.environ.get("KIBANA_URL", "http://127.0.0.1:5601")
    auth = base64.b64encode(f"{os.environ.get('KIBANA_USER', 'elastic')}:{password}".encode()).decode()
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json", "Authorization": "Basic " + auth}
    ctx = ssl._create_unverified_context()

    def call(path: str, method: str = "GET", body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(kib + path, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=60, context=ctx) as response:
            return json.load(response)

    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))["rules"]
    wanted = {rule["rule_id"] for rule in bundle}

    existing = call("/api/detection_engine/rules/_find?per_page=200").get("data", [])
    mine = {r["rule_id"]: r for r in existing if r["rule_id"].startswith(PREFIX)}

    for rule_id, rule in mine.items():
        if rule_id not in wanted:
            call(f"/api/detection_engine/rules?rule_id={rule_id}", "DELETE")
            print(f"deleted {rule_id}")

    created = updated = failed = 0
    for rule in bundle:
        role = rule.pop("role", None)
        body = dict(rule, type="eql", language="eql", tags=["C0015", "lab"])
        if role == "building_block":
            body["building_block_type"] = "default"
        rid = body["rule_id"]
        try:
            if rid in mine:
                call("/api/detection_engine/rules", "PUT", body)
                updated += 1
            else:
                call("/api/detection_engine/rules", "POST", body)
                created += 1
        except urllib.error.HTTPError as exc:
            failed += 1
            print(f"FAILED {rid}: {exc.code} {exc.read().decode()[:160]}")
    print(f"created={created} updated={updated} failed={failed}")
    return 0 if failed == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    b = sub.add_parser("bundle")
    b.add_argument("--out", default="bundle.json")
    a = sub.add_parser("apply")
    a.add_argument("--bundle", default="bundle.json")
    args = parser.parse_args()
    if args.mode == "bundle":
        return build(Path(args.out))
    return apply(Path(args.bundle))


if __name__ == "__main__":
    sys.exit(main())


