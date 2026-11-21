# Validation - one run, one window

The chain was exercised end to end, including boot persistence, in a single window.

| | |
|---|---|
| Window | `2026-11-21T05:00:00Z` - `2026-11-21T05:35:00Z` |
| Stack | Elasticsearch 9.5.3, Sysmon profile `infra/sysmon/sysmon-c0015-balanced.xml` |
| Rule set | 18 shipped |
| Matches | 43 |
| Kibana alert documents | 49 (46 resolved, 3 partial) |

What the run contains:

- document on WS01, macro writes `config.ini` and the HTA, `mshta`, `regsvr32`, loader drops `update.ps1`;
- HealthMonitor runs the script as SYSTEM, downloads `injector.dll` and `beacon.dll`, starts the
  injector; the beacon lands in a SYSTEM `svchost.exe`;
- WMI from WS01 disables Defender on FS01, runs `143.dll`, and the beacon lands in `svchost.exe` there;
- **`persist-task.ps1` creates `C0015Persist` (`/sc onstart /ru SYSTEM`) from the payload**; FS01 is
  rebooted and the injector runs from the task, so the beacon returns in a new `svchost.exe` (PID 788);
- after the reboot the task re-disables Defender, runs `rclone` (exit 0), deletes shadow copies and runs
  the locker (`renamed=40; notes=4`).

## What each rule saw

| Rule | Matches | Note |
|---|---|---|
| R01 | 2 | Word to script host |
| R02 | 1 | script host to regsvr32 |
| R03 | 1 | untrusted module load |
| R04 | 1 | agent runs the planted script |
| R06 | 2 | Defender disabled before the injection and again after the reboot |
| R07 | 3 | wmic calls from WS01 |
| R08 | 3 | WMI children on FS01 |
| R10 | 1 | shadow copies |
| R11 | 1 | rclone transfer |
| R12 | 1 | locker invocation |
| R13 | 1 | script written into checks |
| R14 | 6 | three injections, two threads each: WS01, FS01 before reboot, FS01 after reboot |
| R15 | 7 | module loads, including the post-reboot one |
| R16 | 3 | DNS lookups for `checkauj.com` |
| R17 | 9 | three sequences, each stored as three alert documents (E22, E3, sequence) |
| R19 | 1 | `schtasks /create ... /sc onstart` |

All eighteen shipped rules fired in this run, including R05 (two LSA-secret requests) and R18 (three
discovery documents). R17 contributes nine alert documents because one sequence is stored as three.

## Persistence result

| Check | Result |
|---|---|
| Task created by the payload | `C0015Persist`, `Status: Ready` |
| Task runs at boot | yes, `Last Run` after the reboot |
| Beacon after reboot | new session `a796ef3b` in `svchost.exe` (PID 788), user `C0015\FS01$` |
| Impact after reboot | `fs01_task.log` all gates pass, `renamed=40; notes=4` |

Defender re-enabled itself at boot; the task had to disable it again before the impact step. That is a
property of the lab image, not of the chain.

## Limits

- E8 is collected only for `svchost.exe` targets; injection into other processes is out of scope for R14.
- E7 includes all of `C:\ProgramData\`; the `c0015` entry is inside that broader include.
- No receiver-side evidence for exfiltration; R11 proves the invocation, not the delivery.
- A match is not a verdict.


## Rule changes and controls

| Rule | Change | Replay result |
|---|---|---|
| R02 | matches `process.args` (`*.jpg`, Public, AppData) instead of a command-line substring | run-3 1, run-4 1 (unchanged) |
| R05 | exact argument `lsadump::secrets` | run-3 1, run-4 0 (unchanged) |
| R12 | exact flags `-m -net -nomutex -p` | run-3 1, run-4 1 (unchanged) |
| R18 | kept on command line | run-3 4, run-4 0 (unchanged) |

The argument migration for R18 would raise run-3 from four to six documents (`net.exe` and `net1.exe`
both match the group branches), so it was not shipped.

Fixture controls for R02/R04/R05/R06/R12/R18 were attempted on a synthetic index, but every query
returned zero there, including the positive documents. That is a fixture problem, not a rule result; the
controls are **not** confirmed. The positive replay above is engine output on the real runs.

## Run 6 - replay with all post-compromise actions over C2

| | |
|---|---|
| Window | `2026-11-21T11:42:00Z` - `2026-11-21T12:08:00Z` |
| Bundle | [`evidence/runs/run-6/`](../evidence/runs/run-6/run.json) (`cap-run6-1`) |
| Alert documents | 48 from 18 rules (45 resolved, 3 partial) |
| Ancestor entries without a locator | 6, all nested `signal` ancestors that carry no `_index`; the alert document itself is resolved |
| Session path | docm -> mshta -> regsvr32 -> `update.ps1` -> injector -> `svchost.exe`; every later action issued from the Sliver session on WS01 |

The chain reached the same end state as the run above (boot persistence, post-reboot beacon,
`renamed=40; notes=4`) but the FS01 side was driven only by WMI with the credential recovered from
`_SC_C0015Backup`; no WinRM or RDP was used in the attack path, and the FS01 reboot was an operator
action. Per-alert locators are in [`run-6-alerts.md`](run-6-alerts.md), and the raw log excerpts are in
the `## Evidence` block of each `kill-chain/techniques/*/README.md` page.

Differences worth recording: 18 rules produced documents (R18 fired here, R05 fired here), and the
post-reboot session is `51cd245d` in `svchost.exe` PID 772 rather than the PID in the table above.

