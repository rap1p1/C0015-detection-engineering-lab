# Validation - one run, one window

The whole chain was exercised once, with the beacon generated against the campaign domain, and every
shipped rule was checked inside that single window.

| | |
|---|---|
| Window | `2026-11-20T16:45:00Z` - `2026-11-20T17:05:00Z` |
| Stack | Elasticsearch 9.5.3, Sysmon profile `infra/sysmon/sysmon-c0015-balanced.xml` |
| Rule set | 17 shipped, 1 retired (R09) |
| Matches | 33 |
| Kibana alerts | 35 in `16:45-17:10Z` (the scheduler window runs past the engine window) |

What the run contains:

- document open on WS01, macro writes `config.ini` and the HTA, `mshta`, `regsvr32`, loader drops
  `update.ps1`;
- HealthMonitor runs the script as SYSTEM, downloads `injector.dll` and `beacon.dll`, starts
  `rundll32 injector.dll,Run`; the injector puts the beacon into a SYSTEM `svchost.exe`;
- discovery from the SYSTEM context: `net group "domain admins" /dom`, `net localgroup administrator`,
  `nltest /domain_trusts /all_trusts`, `net view /all /domain`, `tasklist /s FS01`, `ping`;
- `mimikatz lsadump::secrets` returns the `_SC_C0015Backup` secret for `C0015\Administrator`;
- WMI from WS01 disables Defender on FS01, then runs `143.dll` (the injector) and the beacon lands in a
  SYSTEM `svchost.exe` on FS01;
- `fs01-task.ps1`: defences pass, injection pass, `rclone` exit 0, `vssadmin delete shadows`, locker
  `renamed=40; notes=4`.

## Injection hits

Each injection starts two remote threads, so R14 counts two events per attempt.

| Host | Threads | Count |
|---|---|---|
| WS01 | LoadLibrary + StartW | 2 |
| FS01 | LoadLibrary + StartW | 2 |

R15 has five matches:

- `svchost.exe` loads `beacon.dll` on WS01 and on FS01: the target side of the injection;
- `rundll32.exe` loads `beacon.dll` on both hosts: the injector's own local mapping;
- `rundll32.exe` loads `injector.dll`: the injector itself.

Two of the five confirm the service-host load; the others are the source side. That is why R15 is a
building block.

## Network and discovery hits

| Rule | Count | What it saw |
|---|---|---|
| R16 | 2 | `svchost.exe` resolves `checkauj.com` on WS01 and FS01 |
| R17 | 2 | the lookup is followed by `svchost -> 192.168.50.100:443` within five minutes |
| R18 | 4 | the discovery commands above, from the SYSTEM context |

The IP-based beacon from earlier runs produced no DNS event at all. This run uses the domain, so E22 and
E3 are both present, and the two network rules no longer need a separate run.

## Limits

- E8 is collected only for `svchost.exe` targets (profile filter); injection into other processes is out
  of scope for R14.
- E7 includes all of `C:\ProgramData\`; the `c0015` entry sits inside that broader include.
- There is no receiver-side evidence for the exfiltration; R11 proves the invocation, not the delivery.
- A match is not a verdict: the engine proves the query and the fields, not precision.
