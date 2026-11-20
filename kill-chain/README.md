# Kill chain

The scenario reproduced in this lab, from the document that starts it to the ransomware that ends it.
Every phase maps to a folder under `techniques/`, and every folder carries the telemetry the phase
produces plus the captures taken from Elastic and from the manual run.

## Chain at a glance

```
WS01  duc.user (standard)
  document -> macro -> cmd -> mshta -> regsvr32 (loader)
  loader writes a script into the HealthMonitor agent directory

WS01  SYSTEM
  HealthMonitor (LocalSystem) runs the script
  script starts the C2 beacon                        -> session as SYSTEM
  mimikatz lsadump::secrets                          -> C0015\Administrator password (LSA secret)

WS01 -> FS01
  WMI with the recovered credential: disable Defender/ASR, verify
  upload beacon, install it as a service (LocalSystem, auto)   -> session on FS01, survives reboot

FS01  SYSTEM (beacon)
  discovery, exfil with rclone to MEGA
  shadow copies deleted, ransomware runs over the data
```

## Phases and folders

| # | Phase | Folder | Account | Primary telemetry | Rule |
|---|---|---|---|---|---|
| 1 | Document and macro | [`techniques/delivery-macro-document`](techniques/delivery-macro-document/README.md) | duc.user | Sysmon 1 | R01 |
| 2 | HTA proxy execution | [`techniques/hta-proxy-execution`](techniques/hta-proxy-execution/README.md) | duc.user | Sysmon 1 | R02 |
| 3 | Loader and unsigned module | [`techniques/regsvr32-loader`](techniques/regsvr32-loader/README.md) | duc.user | Sysmon 1, 7 | R03 |
| 4 | Agent privilege escalation | [`techniques/agent-privilege-escalation`](techniques/agent-privilege-escalation/README.md) | duc.user -> SYSTEM | Sysmon 1, 11 | R04 |
| 5 | Credential access from LSA secrets | [`techniques/credential-access-lsa-secrets`](techniques/credential-access-lsa-secrets/README.md) | SYSTEM | Sysmon 1, Security 4688 | R05 |
| 6 | WMI lateral movement | [`techniques/wmi-lateral-movement`](techniques/wmi-lateral-movement/README.md) | Administrator -> SYSTEM | Security 4624/4672, Sysmon 1 | R07 / R08 |
| 7 | Beacon service persistence | [`techniques/beacon-service-persistence`](techniques/beacon-service-persistence/README.md) | SYSTEM | Security 7045, Sysmon 1 | R09 |
| 8 | Discovery | [`techniques/discovery`](techniques/discovery/README.md) | SYSTEM | Sysmon 1 | R17 |
| 9 | Exfiltration | [`techniques/rclone-exfiltration`](techniques/rclone-exfiltration/README.md) | SYSTEM | Sysmon 1 | R11 |
| 10 | Ransomware | [`techniques/conti-ransomware`](techniques/conti-ransomware/README.md) | SYSTEM | Sysmon 1, 11 | R12 |

## Accounts

| Account | Rights | Role in the chain |
|---|---|---|
| `C0015\duc.user` | standard user, `Remote Desktop Users` on WS01 | opens the document, runs the loader |
| `C0015\Administrator` | domain administrator (RID 500) | credential recovered from LSA secrets |
| `NT AUTHORITY\SYSTEM` / machine account | local system | agent child, beacon, service, impact |

`helpdesk`, `IT-Support`, `it.admin` and `bk.admin` are not part of this chain.

## Evidence status

Each technique folder has an `## Evidence` section with two placeholders:

- `elastic-<phase>.png` - the alert or event as it appears in Kibana,
- `manual-<phase>.png` - the screen from the manual run.

They are intentionally empty until the first run of this chain is captured. Do not add images before the
corresponding documents exist.

## Rules

The thirteen rules in `detections/` cover this chain from the document edge to the locker and were
validated against the 2026-11-20 run. The catalog records each rule's role, ATT&CK mapping and match count.

