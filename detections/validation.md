# Validation - one run, one window

Supersedes the earlier split between a delivery window (`11:30Z-12:10Z`) and an injection-only window
(`15:20Z-15:45Z`). The numbers below come from `detections/tools/engine_check.py` against the single run
that went from the document to the impact.

| | |
|---|---|
| Window | `2026-11-20T15:40:00Z` - `2026-11-20T16:00:00Z` |
| Stack | Elasticsearch 9.5.3, Sysmon profile `infra/sysmon/sysmon-c0015-balanced.xml` |
| Rule set | 14 shipped, 1 retired (R09) |
| Matches | 42, equal to the 42 alerts created by the Kibana scheduler in the same window |

Per-rule counts are in `detections/catalog.json` and the table in `detections/README.md`.

## R14 - the four matches are two injections

Each injection starts two remote threads (the `LoadLibraryA` call and the `StartW` call), so the rule
counts two events per attempt.

| Host | Time (UTC) | Threads | Locator |
|---|---|---|---|
| WS01 | 15:45:37 | 1976, 7880 | `AaH5opKtksj2Z02HQScP`, `AaH5opKtksj2Z02HQScR` |
| FS01 | 15:51:23 | 4228, 4232 | `AaH5p5Ktksj2Z03TT7WS`, `AaH5p5Ktksj2Z03TT7WT` |

Do not read "4 matches" as four injections. The event carries `TargetImage` but not a target process
GUID in this pipeline, so the correlation with R15 is by host and timestamp, not by identity.

## R15 - five matches, only two are the service host

| Host | Process | Path | Meaning |
|---|---|---|---|
| WS01 | `svchost.exe` | `C:\ProgramData\c0015\beacon.dll` | the injected module in the target (evidence for R14) |
| WS01 | `rundll32.exe` | `C:\ProgramData\c0015\beacon.dll` | the injector's local mapping before the remote call (source-side noise) |
| WS01 | `rundll32.exe` | `C:\ProgramData\c0015\injector.dll` | the injector itself, loaded by rundll32 |
| FS01 | `svchost.exe` | `C:\ProgramData\beacon.dll` | the injected module in the target |
| FS01 | `rundll32.exe` | `C:\ProgramData\beacon.dll` | the injector's local mapping |

Two of the five confirm the service-host load; the other three are the source side. That is why R15 is a
building block and not an alert.

## Relationship to the alert count

The engine counts query matches; the Kibana scheduler counts alerts. In this window both are 42. They
are the same events, but a rule with `building_block` role can still add a match without producing an
alert, so keep the two numbers separate in future runs.

## Limits

- E8 is collected only for `svchost.exe` targets (profile filter), so the rule does not cover injection
  into other processes.
- E7 includes all of `C:\ProgramData\`; the `c0015` entry is inside that broader include, not the reason
  the path is visible.
- No network event (E3) or receiver-side evidence is part of this validation.
