# Kibana queries for run-6

Data views:

- Sysmon: `logs-windows.sysmon_operational-*`
- Security: `logs-system.security-*`
- Alerts: Security -> Alerts (no data view needed)

Time range for run-6 (absolute): **2026-11-21 11:45:00 - 12:10:00 UTC** (Kibana displays it in your
browser zone, 18:45 - 19:10 Asia/Bangkok).

KQL notes: values with spaces or special characters go in double quotes; `*` is a wildcard; combine with
`and` / `or`. Add these columns before taking a screenshot: `@timestamp`, `host.name`, `user.name`,
`process.name`, `process.parent.name`, `process.command_line`, `file.path`,
`winlog.event_data.TargetImage`.

## Delivery and execution

| # | What to show | KQL |
|---|---|---|
| 1 | Office starts a script host | `event.code:1 and process.parent.name:("WINWORD.EXE" or "EXCEL.EXE" or "POWERPNT.EXE" or "OUTLOOK.EXE") and process.name:("mshta.exe" or "cmd.exe" or "wscript.exe" or "cscript.exe" or "powershell.exe")` |
| 2 | HTA host | `event.code:1 and process.name:"mshta.exe"` |
| 3 | Loader invocation | `event.code:1 and process.name:"regsvr32.exe"` |
| 4 | Untrusted module load | `event.code:7 and process.name:"regsvr32.exe" and dll.code_signature.trusted:false` |
| 5 | Script written into the agent checks | `event.code:11 and file.path:*HealthMonitor*checks*` |
| 6 | Agent runs the script | `event.code:1 and process.name:"powershell.exe" and process.command_line:*HealthMonitor*checks*` |
| 7 | All three delivery alerts | `kibana.alert.rule.rule_id:("c0015-r01" or "c0015-r02" or "c0015-r03")` in Security -> Alerts |

## Discovery

| # | What to show | KQL |
|---|---|---|
| 8 | Domain group enumeration | `event.code:1 and process.name:("net.exe" or "net1.exe") and process.command_line:*domain admins*` |
| 9 | Trust enumeration | `event.code:1 and process.name:"nltest.exe"` |
| 10 | Local group enumeration | `event.code:1 and process.name:("net.exe" or "net1.exe") and process.command_line:*localgroup*` |
| 11 | Connectivity check | `event.code:1 and process.name:"ping.exe"` |
| 12 | All discovery events | `event.code:1 and process.name:("net.exe" or "net1.exe" or "nltest.exe" or "ping.exe" or "tasklist.exe")` |
| 13 | R18 alerts | `kibana.alert.rule.rule_id:"c0015-r18"` in Security -> Alerts |

## Credential access

| # | What to show | KQL |
|---|---|---|
| 14 | LSA secret request | `event.code:1 and process.command_line:*lsadump::secrets*` |
| 15 | Mimikatz process | `event.code:1 and process.name:"mimi.exe"` |
| 16 | R05 alert | `kibana.alert.rule.rule_id:"c0015-r05"` in Security -> Alerts |

## WMI and lateral movement

| # | What to show | KQL |
|---|---|---|
| 17 | Remote process creation request | `event.code:1 and process.name:("WMIC.exe" or "wmic.exe") and process.command_line:*process call create*` |
| 18 | WMI provider child | `event.code:1 and process.parent.name:"WmiPrvSE.exe"` |
| 19 | Network logon on FS01 | `event.code:4624 and winlog.event_data.LogonType:3 and winlog.event_data.TargetUserName:"Administrator"` |
| 20 | WMI children on FS01 | `event.code:1 and host.name:"fs01" and process.parent.name:"WmiPrvSE.exe"` |
| 21 | R07 and R08 alerts | `kibana.alert.rule.rule_id:("c0015-r07" or "c0015-r08")` in Security -> Alerts |

## Injection

| # | What to show | KQL |
|---|---|---|
| 22 | Remote thread into svchost | `event.code:8 and process.name:"rundll32.exe" and winlog.event_data.TargetImage:*svchost.exe` |
| 23 | Beacon module loaded | `event.code:7 and dll.path:(*ProgramData*c0015* or *ProgramData*beacon.dll)` |
| 24 | Injector invocation | `event.code:1 and process.name:"rundll32.exe" and process.command_line:*143.dll*` |
| 25 | R14 and R15 alerts | `kibana.alert.rule.rule_id:("c0015-r14" or "c0015-r15")` in Security -> Alerts |

## Network

| # | What to show | KQL |
|---|---|---|
| 26 | Campaign domain lookup | `event.code:22 and dns.question.name:"checkauj.com"` |
| 27 | Connection to the listener | `event.code:3 and destination.ip:"192.168.50.100" and destination.port:443` |
| 28 | svchost outbound 443 | `event.code:3 and process.name:"svchost.exe" and destination.port:443` |
| 29 | R16 and R17 alerts | `kibana.alert.rule.rule_id:("c0015-r16" or "c0015-r17")` in Security -> Alerts |

## Persistence

| # | What to show | KQL |
|---|---|---|
| 30 | Boot task creation | `event.code:1 and process.name:"schtasks.exe" and process.command_line:*onstart*` |
| 31 | Task by name | `event.code:1 and process.command_line:*C0015Persist*` |
| 32 | R19 alert | `kibana.alert.rule.rule_id:"c0015-r19"` in Security -> Alerts |

## Exfiltration and impact

| # | What to show | KQL |
|---|---|---|
| 33 | rclone | `event.code:1 and process.name:"rclone.exe"` |
| 34 | Shadow copy deletion | `event.code:1 and process.name:"vssadmin.exe" and process.command_line:*shadows*` |
| 35 | Locker invocation | `event.code:1 and process.name:("ransomware-sim.exe" or "locker.exe")` |
| 36 | Notes written | `event.code:11 and file.name:"readme.txt"` |
| 37 | Ransom-note extension written | `event.code:11 and file.name:*.c0015` |
| 38 | R10, R11, R12 alerts | `kibana.alert.rule.rule_id:("c0015-r10" or "c0015-r11" or "c0015-r12")` in Security -> Alerts |

## Whole-chain views

| # | What to show | KQL |
|---|---|---|
| 39 | Process chain on both hosts | `event.code:1 and host.name:("ws01" or "fs01") and process.name:("WINWORD.EXE" or "mshta.exe" or "regsvr32.exe" or "powershell.exe" or "rundll32.exe" or "mimi.exe" or "net.exe" or "net1.exe" or "nltest.exe" or "WMIC.exe" or "schtasks.exe" or "rclone.exe" or "vssadmin.exe" or "ransomware-sim.exe")` |
| 40 | All file writes of interest | `event.code:11 and file.path:(*HealthMonitor* or *ProgramData*c0015* or */corpus/*)` |
| 41 | Everything the rules can see | `event.code:(1 or 3 or 7 or 8 or 11 or 22) and host.name:("ws01" or "fs01")` |

## Alerts

| # | What to show | Query |
|---|---|---|
| 42 | All C0015 alerts | Security -> Alerts, `kibana.alert.rule.rule_id: c0015-*`, time range 11:45-12:10 UTC. Expect **48** rows. |
| 43 | Alerts per host | Add `host.name` as a field/filter: `host.name:"ws01"` or `host.name:"fs01"` |
| 44 | One rule at a time | Replace the rule id: `c0015-r14`, `c0015-r17`, `c0015-r19`, ... |

## Expected counts for the screenshot check

Run-6: 48 alert documents from 18 rules.

| Rule | Docs | Rule | Docs |
|---|---:|---|---:|
| R01 | 2 | R11 | 1 |
| R02 | 1 | R12 | 1 |
| R03 | 1 | R13 | 1 |
| R04 | 1 | R14 | 6 |
| R05 | 2 | R15 | 7 |
| R06 | 2 | R16 | 3 |
| R07 | 3 | R17 | 9 |
| R08 | 3 | R18 | 3 |
| R10 | 1 | R19 | 1 |

R17 is nine documents because each of the three sequences is stored as three alerts (E22, E3, sequence).
