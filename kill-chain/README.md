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
| 1 | Document and macro | [`techniques/delivery-macro-document`](techniques/delivery-macro-document/README.md) | duc.user | Sysmon 1, 11 | R01 |
| 2 | HTA proxy execution | [`techniques/hta-proxy-execution`](techniques/hta-proxy-execution/README.md) | duc.user | Sysmon 1 | R02 |
| 3 | Loader and untrusted module | [`techniques/regsvr32-loader`](techniques/regsvr32-loader/README.md) | duc.user | Sysmon 1, 7 | R03 |
| 4 | Agent privilege escalation | [`techniques/agent-privilege-escalation`](techniques/agent-privilege-escalation/README.md) | duc.user -> SYSTEM | Sysmon 1, 11 | R04, R13 |
| 5 | Credential access from LSA secrets | [`techniques/credential-access-lsa-secrets`](techniques/credential-access-lsa-secrets/README.md) | SYSTEM | Sysmon 1 | R05 |
| 6 | WMI lateral movement | [`techniques/wmi-lateral-movement`](techniques/wmi-lateral-movement/README.md) | Administrator -> SYSTEM | Security 4624, Sysmon 1, 8 | R06, R07, R08 |
| 7 | Injection into the service host | [`techniques/process-injection`](techniques/process-injection/README.md) | SYSTEM | Sysmon 7, 8 | R14, R15 |
| 8 | Discovery | [`techniques/discovery`](techniques/discovery/README.md) | SYSTEM | Sysmon 1 | (operator step) |
| 9 | Exfiltration | [`techniques/rclone-exfiltration`](techniques/rclone-exfiltration/README.md) | SYSTEM | Sysmon 1 | R11 |
| 10 | Ransomware | [`techniques/conti-ransomware`](techniques/conti-ransomware/README.md) | SYSTEM | Sysmon 1 | R10, R12 |

## Accounts

| Account | Rights | Role in the chain |
|---|---|---|
| `C0015\duc.user` | standard user, `Remote Desktop Users` on WS01 | opens the document, runs the loader |
| `C0015\Administrator` | domain administrator (RID 500) | credential recovered from LSA secrets |
| `NT AUTHORITY\SYSTEM` / machine account | local system | agent child, injector, beacon inside svchost, impact |

`helpdesk`, `IT-Support`, `it.admin` and `bk.admin` are not part of this chain.

## Evidence status

Each technique folder has an `## Evidence` section with the captures from run-6. The screenshots live
under [`docs/evidence/run-6/`](../docs/evidence/run-6/README.md), grouped by phase; the technique page
embeds the ones that belong to it and keeps the Elastic excerpts next to them.

## Rules

The fourteen rules in `detections/` cover this chain from the document edge to the locker. The catalog
records each rule's role, ATT&CK mapping and match count; R14 and R15 were validated on the injection test,
the delivery rules on the earlier document run.

