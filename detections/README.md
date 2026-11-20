# Detection content

The rule package is defined by [`catalog.json`](catalog.json). The table in [`INDEX.md`](INDEX.md) is
generated from it and must not be edited by hand:

```
python3 tools/detections/catalog.py --check     # verify package (CI gate)
python3 tools/detections/catalog.py --index     # regenerate INDEX.md
python3 tools/detections/catalog.py --update    # refresh content hashes
```

`--check` fails on a rule file that is missing, untracked, ignored by `.gitignore`, changed without a
catalog update, referenced twice, or present on disk without a catalog entry.

## What a catalog entry carries

| Field | Meaning |
|---|---|
| `id` | stable identifier (`C0015-R01`); retired ids are never reused |
| `revision` | incremented when the query or its claim changes |
| `file` + `sha256` | the query and a content hash |
| `status` | `shipped` or `retired`; retired entries keep a reason and no file |
| `role` | `alert`, `building_block`, `enrichment`, or `hunt` |
| `severity`, `risk_score` | used when the rule is imported |
| `attck` | tactic and technique id, no more than the query supports |
| `prerequisites` | the events and configuration the query depends on |
| `limitations` | what the query does not prove |
| `deployment` | index patterns, timestamp field, interval, lookback, `max_signals`, enabled state |
| `validation` | the stack, window, match count and truncation flag from the last engine run |

## Roles

- **alert** - a behaviour worth an analyst's attention on its own.
- **building_block** - a precise observation that is too common to alert alone; meant to be correlated.
- **enrichment** - context attached to another alert (interactive logon, operator habit).
- **hunt** - a starting point for a hypothesis, not a detector.

The role is part of the claim. A `building_block` described in prose as a finished detection is a
documentation bug, not a detection.

## Deployment contract

Every entry records the index patterns, the timestamp field, the schedule and the signal cap that are
applied by `tools/detections/kibana_bundle.py`. That tool builds the payload from the catalog and applies
it as an explicit operator step, gated on `KIBANA_PASS`, and it maps the catalog role to the deployment:
rules whose role is `building_block` are created with `building_block_type: default`, and no rule is
given a notification action. Nothing runs in CI.

Two things must stay true when the rules are imported into a stack:

1. the index patterns must match the data the sensors actually write, and
2. the field names in the queries must exist in that pipeline.

Neither is proven by a query parsing. See the evidence schema in
[`evidence/schema/export-v1.schema.json`](../evidence/schema/export-v1.schema.json)
for the fields an export must carry to be checkable.
## Validation status

All thirteen rules were run with `detections/tools/engine_check.py` against Elasticsearch 9.5.3 on the
window `2026-11-20T11:30Z -> 2026-11-20T12:10Z`, the run that exercised the current chain. Every query
parsed and every field it names exists in this pipeline; the matches are in each catalog entry.

| Rule | Matches | Meaning |
|---|---|---|
| R01 | 2 | Word started mshta through cmd |
| R02 | 2 | mshta started regsvr32 on the staged `.jpg` |
| R03 | 2 | regsvr32 loaded the unsigned module |
| R04 | 1 | HealthMonitor ran the planted script as SYSTEM |
| R05 | 3 | mimikatz read LSA secrets |
| R06 | 0 | no LSASS access in this chain; the rule stays for the technique |
| R07 | 1 | wmic created a process on FS01 |
| R08 | 1 | the WMI provider host started PowerShell on FS01 |
| R09 | 1 | the beacon was installed as a service from ProgramData |
| R10 | 1 | shadow copies deleted |
| R11 | 1 | rclone copied the corpus to a remote |
| R12 | 1 | the locker started with its deployment flags |
| R13 | 6 | service binaries ran from user paths (context) |

A match is not a verdict: the engine check proves the query and the fields, not precision. R13 is a
building block; R06 has no match in this run because the chain reads LSA secrets instead of LSASS.

## Field notes

- `E7` carries the module in `dll.path` and the trust verdict in `dll.code_signature.trusted`, not in
  `winlog.event_data.ImageLoaded`.
- `7045` carries `winlog.event_data.ImagePath`, `ServiceName`, `StartType` and `AccountName`; R09 keys on
  the image path.
- The note file is not visible in `E11` with the current Sysmon profile, which is why R12 keys on the
  locker command line instead of the note.
- `E10` `GrantedAccess` is a string such as `0x1010`; the rule lists the masks and excludes the security
  and hypervisor agents that read LSASS legitimately.
