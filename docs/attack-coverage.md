# ATT&CK coverage

Techniques exercised by the lab, the folder that implements each one, and the rule that detects it.
Rule counts in the README are derived from this table.

| Tactic | Technique | ID | Lab technique folder | Primary rule |
|---|---|---|---|---|
| Execution | User Execution: Malicious File | T1204.002 | `macro-document-delivery` | `office-spawns-cmd.yml` |
| Execution | Command and Scripting Interpreter: Visual Basic | T1059.005 | `macro-document-delivery` | `office-spawns-cmd.yml` |
| Defense Evasion | System Binary Proxy Execution: Mshta | T1218.005 | `hta-proxy-execution` | `mshta-downloads-and-executes.yml` |
| Defense Evasion | System Binary Proxy Execution: Regsvr32 | T1218.010 | `regsvr32-module-execution` | `regsvr32-unsigned-module-user-path.yml` |
| Defense Evasion | System Binary Proxy Execution: Rundll32 | T1218.011 | `bazar-svchost-stage` | `svchost-spawns-rundll32.yml` |
| Defense Evasion | Masquerading: Double File Extension | T1036.007 | `regsvr32-module-execution` | `regsvr32-unsigned-module-user-path.yml` |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.001 | cross-technique | `rundll32-loads-unsigned-module-from-programdata.yml` |
| Defense Evasion | Process Injection | T1055 | `winlogon-injection` | `rundll32-injects-system-process.yml` |
| Defense Evasion | Process Injection: Portable Executable Injection | T1055.002 | `winlogon-injection` | `rundll32-injects-system-process.yml` |
| Persistence | Create or Modify System Process: Windows Service | T1543.003 | `bazar-svchost-stage` | `svchost-spawns-rundll32.yml` |
| Discovery | System Owner/User Discovery | T1033 | `lolbin-discovery` | `winlogon-spawns-shell.yml` |
| Discovery | System Information Discovery | T1082 | `lolbin-discovery` | `discovery-lolbin-burst.yml` |
| Discovery | Process Discovery | T1057 | `lolbin-discovery` | `winlogon-spawns-shell.yml` |
| Discovery | Account Discovery: Domain Account | T1087.002 | `lolbin-discovery` | `discovery-lolbin-burst.yml` |
| Discovery | Account Discovery: Local Account | T1087.001 | `lolbin-discovery` | `discovery-lolbin-burst.yml` |
| Discovery | Domain Trust Discovery | T1482 | `lolbin-discovery` | `discovery-lolbin-burst.yml` |
| Discovery | Remote System Discovery | T1018 | `lolbin-discovery` | `discovery-lolbin-burst.yml` |
| Discovery | System Time Discovery | T1124 | `lolbin-discovery` | `winlogon-spawns-shell.yml` |
| Discovery | Network Share Discovery | T1135 | `share-enumeration` | `powerview-sharefinder-cradle.yml` |
| Lateral Movement | Windows Management Instrumentation | T1047 | `wmi-remote-process-creation` | `wmiprvse-spawns-rundll32.yml` |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | `wmi-remote-process-creation` | `wmic-process-create-rundll32.yml` |
| Lateral Movement | Remote Services: RDP | T1021.001 | `rdp-lateral-movement` | `beacon-process-opens-rdp.yml` |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | `processhacker-lsass-access` | `lsass-access-read-mask.yml` |
| Collection | Data from Network Shared Drive | T1039 | `rclone-exfiltration` | `rclone-to-cloud-storage.yml` |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | `svchost-injection` | `service-host-egress.yml` |
| Command and Control | Application Layer Protocol: DNS | T1071.004 | `bazar-svchost-stage` | `dns-nxdomain-beacon-retry.yml` |
| Command and Control | Remote Access Software | T1219.002 | `anydesk-deployment` | `remote-access-tool-in-user-media-path.yml` |
| Exfiltration | Exfiltration Over Web Service: Exfiltration to Cloud Storage | T1567.002 | `rclone-exfiltration` | `rclone-to-cloud-storage.yml` |
| Exfiltration | Data Transfer Size Limits | T1030 | `rclone-exfiltration` | `rclone-to-cloud-storage.yml` |
| Impact | Data Encrypted for Impact | T1486 | `conti-style-impact` | `locker-binary-argument-set.yml` |

## Rule inventory

| Location | Rules |
|---|---|
| `techniques/*/detection_rules/sigma/` | 19 Sigma rules, one to three per technique |
| `detections/sigma/` | 1 cross-technique Sigma rule |
| `detections/suricata/` | 5 network signatures: jQuery profile URIs, certificate subject, unresolved fallback domain, MEGA API hostname |
| `detections/yara/` | 1 file rule for the Go beacon module |

## Signals that are not covered by a rule

| Behaviour | Why no rule | Where it is observable |
|---|---|---|
| File deletion and rename during impact | Sysmon file-delete archiving is disabled in the balanced profile; the note spread is the reliable signal | Event 11 for `readme.txt`, event 26 when the capture profile is applied |
| Backup console usage | GUI action with no process of its own | Session recording and window title telemetry |
| Credential material recovered from the dump | Offline operation on the dump | Process creation of the parsing tool, delete event for the dump |
