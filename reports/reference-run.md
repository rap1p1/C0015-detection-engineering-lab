# Reference run

| Field | Value |
|---|---|
| Run id | `run-1` |
| Execution window (UTC) | 2026-10-27T12:20:50Z - 2026-10-27T12:28:45Z |
| Capture window (UTC) | 2026-10-27T12:20:00Z - 2026-10-27T12:40:00Z |
| Stack | Elasticsearch 9.5.3, Kibana 9.5.3 |
| Rule set | catalog revision 3, 15 shipped rules, 7 with the building-block role |
| Evidence | [`evidence/runs/run-1/`](../evidence/runs/run-1/run.json) (capture `cap-run1-2`) |

The scenario is executed by opening the macro document in the victim session. The operator actions are
the reset before the run and the two sessions the chain needs, both opened after the window starts.

This bundle is a **recapture** of the same execution window. The first capture (`run-1`) wrote an
empty `alert_source_documents.json` because it read `kibana.alert.ancestors` as a nested object while the
field is stored as a dotted key. The execution did not change; only the capture was re-run, and the
superseded bundle is kept beside it.

## Alerts

**33 C0015 alert documents from 12 rules**, plus one document from an unrelated laboratory rule. Every
C0015 alert resolves to exactly one source event: `sources.by_alert.json` holds 33 links and
`sources/unresolved.json` is empty. The counts below are the documents in the export, grouped by the
host carried on each document.

| Rule | Role | Alerts | Hosts |
|---|---|---|---|
| R12 note creation | building_block | 7 | WS01 1 (staging), FS01 6 (five corpus notes, `C:\readme.txt`) |
| R17 discovery command | building_block | 6 | WS01 6 |
| R06 wmi remote creation | building_block | 5 | WS01 5 |
| R18 wmi shell execution | building_block | 4 | FS01 4 |
| R13 rdp interactive logon | enrichment | 3 | FS01 2, WS01 1 |
| R03 loader loads unsigned module | alert | 2 | WS01 2 |
| R01 office spawns script host | building_block | 1 | WS01 1 |
| R02 script host starts loader | building_block | 1 | WS01 1 |
| R04 injection into system process | alert | 1 | FS01 1 |
| R05 lsass credential access | alert | 1 | FS01 1 |
| R07 wmi loader execution | alert | 1 | FS01 1 |
| R11 rclone transfer intent | alert | 1 | WS01 1 |

Seven rules carry the building-block role in the catalog (R01, R02, R06, R08, R12, R17, R18). Six of
them produced documents in this run and each document carries `kibana.alert.building_block_type =
default`, so the 24 documents are signals rather than visible alerts; R08 did not fire because the chain
does not create a `svchost -> loader` edge. R13 is enrichment: it produces documents but is not a
notification.

## Stage mapping

| Stage | Behaviour | Rule | Evidence |
|---|---|---|---|
| Delivery | Word starts a script host, script host starts regsvr32 | R01, R02 | `events/alert_source_documents.json` |
| Loader | regsvr32 loads an unsigned module from the staging path | R03 | same |
| SYSTEM pivot | scheduled task runs the stager | - | not covered by a rule |
| Spray | helpdesk password guess against the target | R15 (0) | `context/logon.json` |
| Discovery | `whoami /all`, `nltest`, `net group`, `net view`, `tasklist /s`, `ping` on WS01 | R17 | alert sources |
| WMI pivot | `wmic process call create` from WS01 | R06, R07, R18 | alert sources |
| Persistence | `C0015Persist` scheduled task | - | not covered by a rule |
| Injection | remote thread into `svchost -k UnistackSvcGroup` | R04 | alert sources |
| Credential access | LSASS access, mask `0x1010` | R05 | alert sources |
| Exfiltration | `rclone copy ... Mega:DATA` from WS01 | R11 | alert sources |
| Impact | five corpus notes, forty renamed files | R12 | alert sources |
| Interactive access | RDP sessions, helpdesk on FS01 and one on WS01 | R13 | alert sources |

## Rules that did not fire

| Rule | Reason |
|---|---|
| R15 repeated failures then success | the three failed `net use` attempts against `\\WS01\IPC$` produced no `4625` for `helpdesk`; the two failures in the window are `duc.user` logon type 4 and 2, outside the hypothesis. The behaviour exists, the telemetry does not. |
| R16 RunAsPPL write | the scenario does not modify `RunAsPPL`; the defence step changes Defender preferences instead. |
| R08 service host starts loader | the chain injects from `wmic -> rundll32`; no `svchost -> loader` edge is produced. |

## Limits

- The impact step renames files and writes a note; it does not encrypt.
- `rclone` exited successfully, but no receiver inventory is captured, so the transfer is intent.
- The spray is visible in the payload log only, not in the security channel.
- `sources/` holds the alert-resolved documents (`by_alert.json`, `unresolved.json`); `context/` holds
  wider queries, each labelled with its query, returned count, total and whether it is a sample. Only
  `sources/` proves which event produced an alert.
- `manifest.json` carries a checksum per file; the validator checks it, the alert-to-source links and the
  counts.

## Reproduce

```
ES_PASS=... C0015_VICTIM_PW=... C0015_HELPDESK_PW=... pwsh tools/run/reference-run.ps1 -RunId run-1

ES_PASS=... python3 tools/evidence/capture_run.py --run-id run-1 \
  --start 2026-10-27T12:20:00Z --end 2026-10-27T12:40:00Z \
  --out evidence/runs/run-1
```







