# ATT&CK coverage

Techniques the lab exercises, the folder that implements each one, and the rule that detects it.

| Tactic | Technique | ID | Technique folder | Rule |
|---|---|---|---|---|
| Initial Access | Spearphishing Attachment | T1566.001 | `macro-document-delivery` | 01 |
| Execution | User Execution: Malicious File | T1204.002 | `macro-document-delivery` | 01 |
| Execution | Command and Scripting Interpreter: Visual Basic | T1059.005 | `hta-proxy-execution` | 01, 02 |
| Defense Evasion | System Binary Proxy Execution: Mshta | T1218.005 | `hta-proxy-execution` | 02 |
| Defense Evasion | System Binary Proxy Execution: Regsvr32 | T1218.010 | `regsvr32-module-execution` | 02 |
| Defense Evasion | System Binary Proxy Execution: Rundll32 | T1218.011 | `bazar-svchost-stage` | 08 |
| Defense Evasion | Hijack Execution Flow | T1574 | `regsvr32-module-execution` | 03 |
| Persistence | Windows Service | T1543.003 | `bazar-svchost-stage` | 08 |
| Privilege Escalation | Thread Execution Hijacking | T1055.003 | `winlogon-injection` | 04 |
| Credential Access | LSASS Memory | T1003.001 | `processhacker-lsass-access` | 05 |
| Credential Access | Password Spraying | T1110.003 | `bazar-svchost-stage` | 15 |
| Lateral Movement | Windows Management Instrumentation | T1047 | `wmi-remote-process-creation` | 06, 07 |
| Lateral Movement | Remote Services: RDP | T1021.001 | `rdp-lateral-movement` | 13 |
| Lateral Movement | Pass the Hash | T1550.002 | `rdp-lateral-movement` | 09 |
| Discovery | Domain Trust Discovery | T1482 | `lolbin-discovery` | 01, 14 |
| Discovery | Network Share Discovery | T1135 | `share-enumeration` | - |
| Discovery | Process Discovery | T1057 | `lolbin-discovery` | 14 |
| Collection | Data from Network Shared Drive | T1039 | `rclone-exfiltration` | 11 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | `hta-proxy-execution` | 03 |
| Exfiltration | Exfiltration to Cloud Storage | T1567.002 | `rclone-exfiltration` | 11 |
| Impact | Data Encrypted for Impact | T1486 | `conti-style-impact` | 12 |
| Impact | Service Stop | T1489 | `conti-style-impact` | 12 |

Discovery through share enumeration has no dedicated rule; it is covered by the collection rule on the
transfer that follows and by the parent edge of the process that runs it.

Rule numbers refer to `detections/eql/`; the index is in [`detections/README.md`](../detections/README.md).
