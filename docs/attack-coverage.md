# ATT&CK coverage

Techniques exercised by the lab, the folder that implements each one, and the rule that detects it.
Rule counts in the README are derived from this table.

| Tactic | Technique | ID | Lab technique folder | EQL rule |
|---|---|---|---|---|
| Execution | User Execution: Malicious File | T1204.002 | `macro-document-delivery` | `office-spawns-shell.eql` |
| Execution | Command and Scripting Interpreter: Visual Basic | T1059.005 | `macro-document-delivery` | `office-spawns-shell.eql` |
| Defense Evasion | System Binary Proxy Execution: Mshta | T1218.005 | `hta-proxy-execution` | `mshta-spawns-loader.eql` |
| Defense Evasion | System Binary Proxy Execution: Regsvr32 | T1218.010 | `regsvr32-module-execution` | `regsvr32-unsigned-image.eql` |
| Defense Evasion | System Binary Proxy Execution: Rundll32 | T1218.011 | `bazar-svchost-stage` | `svchost-spawns-rundll32.eql` |
| Defense Evasion | Masquerading: Double File Extension | T1036.007 | `regsvr32-module-execution` | `regsvr32-unsigned-image.eql` |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.001 | cross-technique | `detections/eql/rundll32-unsigned-module.eql` |
| Defense Evasion | Process Injection | T1055 | `winlogon-injection` | `thread-into-system-process.eql` |
| Defense Evasion | Process Injection: Portable Executable Injection | T1055.002 | `winlogon-injection` | `thread-into-system-process.eql` |
| Persistence | Create or Modify System Process: Windows Service | T1543.003 | `bazar-svchost-stage` | `svchost-spawns-rundll32.eql` |
| Discovery | System Owner/User Discovery | T1033 | `lolbin-discovery` | `winlogon-spawns-shell.eql` |
| Discovery | System Information Discovery | T1082 | `lolbin-discovery` | `winlogon-discovery-burst.eql` |
| Discovery | Process Discovery | T1057 | `lolbin-discovery` | `winlogon-spawns-shell.eql` |
| Discovery | Account Discovery: Domain Account | T1087.002 | `lolbin-discovery` | `winlogon-discovery-burst.eql` |
| Discovery | Account Discovery: Local Account | T1087.001 | `lolbin-discovery` | `winlogon-discovery-burst.eql` |
| Discovery | Domain Trust Discovery | T1482 | `lolbin-discovery` | `winlogon-discovery-burst.eql` |
| Discovery | Remote System Discovery | T1018 | `lolbin-discovery` | `winlogon-discovery-burst.eql` |
| Discovery | System Time Discovery | T1124 | `lolbin-discovery` | `winlogon-spawns-shell.eql` |
| Discovery | Network Share Discovery | T1135 | `share-enumeration` | `sharefinder-cradle.eql` |
| Lateral Movement | Windows Management Instrumentation | T1047 | `wmi-remote-process-creation` | `wmiprvse-spawns-loader.eql` |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | `wmi-remote-process-creation` | `wmic-remote-process-create.eql` |
| Lateral Movement | Remote Services: RDP | T1021.001 | `rdp-lateral-movement` | `implant-opens-rdp.eql` |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | `processhacker-lsass-access` | `lsass-access-read-mask.eql` |
| Collection | Data from Network Shared Drive | T1039 | `rclone-exfiltration` | `rclone-cloud-transfer.eql` |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | `svchost-injection` | `service-host-egress.eql` |
| Command and Control | Application Layer Protocol: DNS | T1071.004 | `bazar-svchost-stage` | `dns-nxdomain-retry.eql` |
| Command and Control | Remote Access Software | T1219.002 | `anydesk-deployment` | `remote-access-tool-in-media-path.eql` |
| Exfiltration | Exfiltration Over Web Service: Exfiltration to Cloud Storage | T1567.002 | `rclone-exfiltration` | `rclone-cloud-transfer.eql` |
| Exfiltration | Data Transfer Size Limits | T1030 | `rclone-exfiltration` | `rclone-cloud-transfer.eql` |
| Impact | Data Encrypted for Impact | T1486 | `conti-style-impact` | `locker-argument-set.eql` |

## Rule inventory

| Location | Rules |
|---|---|
| `techniques/*/detection_rules/eql/` | 19 EQL rules, one to three per technique |
| `detections/eql/` | 1 cross-technique EQL rule |

## Signals that are not covered by a rule

| Behaviour | Why no rule | Where it is observable |
|---|---|---|
| File deletion and rename during impact | Sysmon file-delete archiving is disabled in the balanced profile; the note spread is the reliable signal | Event 11 for `readme.txt`, event 26 when the capture profile is applied |
| Backup console usage | GUI action with no process of its own | Session recording and window title telemetry |
| Credential material recovered from the dump | Offline operation on the dump | Process creation of the parsing tool, delete event for the dump |



