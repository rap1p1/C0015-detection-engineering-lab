# Validation - one run, one window

The chain was exercised end to end, including boot persistence, in a single window.

| | |
|---|---|
| Window | `2026-11-21T05:00:00Z` - `2026-11-21T05:35:00Z` |
| Stack | Elasticsearch 9.5.3, Sysmon profile `infra/sysmon/sysmon-c0015-balanced.xml` |
| Rule set | 18 shipped, 1 retired (R09) |
| Matches | 44 |

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
| R07 | 6 | wmic calls from WS01 |
| R08 | 6 | WMI children on FS01 |
| R10 | 1 | shadow copies |
| R11 | 1 | rclone transfer |
| R12 | 1 | locker invocation |
| R13 | 1 | script written into checks |
| R14 | 6 | three injections, two threads each: WS01, FS01 before reboot, FS01 after reboot |
| R15 | 7 | module loads, including the post-reboot one |
| R16 | 3 | DNS lookups for `checkauj.com` |
| R17 | 3 | each lookup followed by the 443 connection from the same process identity |
| R19 | 1 | `schtasks /create ... /sc onstart` |

R05 (LSA secret) and R18 (discovery) were **not exercised in this run**; they were exercised in run-3.
The catalog records the window above, so their zeroes here are honest, not gaps in the rule.

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
