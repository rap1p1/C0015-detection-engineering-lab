# C0015 - BazarLoader to Conti, rebuilt for detection engineering

A lab that reproduces the C0015 intrusion from a document macro to Conti-style ransomware, and ships the
detection content with it: an EQL rule set in a machine-readable catalog, a kill chain documented phase by
phase, and the attack playbook and tooling needed to run it.

Repository: <https://github.com/rap1p1/C0015-detection-engineering-lab>

## Start here

| Goal | Where |
|---|---|
| Read the chain | [`kill-chain/README.md`](kill-chain/README.md) |
| Run it | [`attack-playbook/README.md`](attack-playbook/README.md) |
| See the tooling | [`tools/README.md`](tools/README.md) |
| Read or deploy the rules | [`detections/catalog.json`](detections/catalog.json), [`detections/README.md`](detections/README.md) |
| Read the investigations | [`reports/cases/`](reports/cases/) |

## The chain

```
WS01 duc.user: document -> macro -> cmd -> mshta -> regsvr32 (loader)
loader writes a script into the HealthMonitor agent directory
HealthMonitor (LocalSystem) runs it -> beacon -> mimikatz lsadump::secrets
-> C0015\Administrator credential
WMI to FS01 with that credential: Defender off, beacon installed as a service
FS01 beacon: discovery, rclone exfil to MEGA, shadow copies deleted, ransomware
```

The privilege escalation does not rely on anything the attacker pre-creates: the lab has one environment
weakness (an agent that executes scripts from a user-writable directory) and one operational weakness (a
maintenance task that runs as the domain administrator, so its password sits in LSA secrets).

## Layout

```
kill-chain/            the chain, one folder per phase, each with its evidence placeholders
attack-playbook/       operator runbook, payloads/ and setup/ for the one-time weaknesses
tools/                 the attack tools, with the exact commands and the telemetry they leave
detections/            catalog, EQL rules, generated index, deployment and engine tooling
docs/                  study (architecture, contract, gaps), detection, operations
infra/                 hosts, accounts, DNS, Sysmon profiles
reports/               cases and tickets
evidence/              bundle schema and capture/validation tooling (runs land here)
```

## Status

- The chain was redesigned in November 2026; the earlier runs and their screenshots were removed, and the
  case files now describe the new chain with evidence marked pending.
- The rule set still reflects the previous chain. R19 (WMI execution), R21 (service install), R22 (agent
  child) and R23 (mimikatz / LSA secrets) are the planned replacements for R06, R08, R13 and R15.
- No claim in `reports/` is backed by a capture of this chain yet.

## Checks

```
python3 detections/tools/catalog.py --check
python3 detections/tools/catalog.py --index && git diff --exit-code detections/INDEX.md
python3 .github/scripts/check_links.py
```

## Scope and credits

The lab runs only on the isolated 192.168.50.0/24 network with synthetic data. Source campaign:
MITRE ATT&CK C0015 and The DFIR Report, "Continuing the Bazar ransomware story" (November 2021). See
[`CREDITS.md`](CREDITS.md).
