# ATT&CK coverage

Generated from [`detections/catalog.json`](../../detections/catalog.json) by
`tools/detections/catalog.py --coverage`. It records what each rule observes, not what the
campaign achieved.

| Tactic | Technique | Rule | Role | What the rule observes | Limitation |
|---|---|---|---|---|---|
| Execution | T1204.002 User Execution: Malicious File | C0015-R01 | alert | An Office process starts a shell or script host from a document. | Benign macros and add-ins produce the same edge; correlate with the loader that follows. |
| Defense Evasion | T1218.010 System Binary Proxy Execution: Regsvr32 | C0015-R02 | alert | mshta, cmd or wscript starts regsvr32 on a file in a user-writable path or with a non-DLL extension. | regsvr32 is also used by installers; the path and extension carry most of the signal. |
| Defense Evasion | T1218.010 System Binary Proxy Execution: Regsvr32 | C0015-R03 | alert | regsvr32 loads an unsigned module from a user-writable path or a file with an image extension. | Unsigned is common for in-house modules; the loading process and path make it a loader. |
| Execution | T1059.001 Command and Scripting Interpreter: PowerShell | C0015-R04 | alert | The monitoring agent starts a PowerShell script from its own checks directory, which users can write to. | The agent is lab infrastructure; in an estate the same rule would key on the specific agent name. |
| Credential Access | T1003.004 OS Credential Dumping: LSA Secrets | C0015-R05 | alert | A credential dumping tool runs with LSA secrets or LSASS module arguments. | Command-line based; an obfuscated tool or a renamed binary without arguments is missed. |
| Defense Evasion | T1562.001 Impair Defenses: Disable or Modify Tools | C0015-R06 | alert | PowerShell or the platform tool weakens Defender: real-time, IOAV, behaviour monitoring, or exclusions. | Administrators legitimately change these settings; the parent process and the host role decide. |
| Execution | T1047 Windows Management Instrumentation | C0015-R07 | alert | wmic creates a process on another host with an explicit credential. | Source-side only; the command line carries the credential and must be redacted in evidence. |
| Execution | T1047 Windows Management Instrumentation | C0015-R08 | alert | The WMI provider host starts a shell, script host or loader on the target. | Management tooling also creates processes through WMI; the child image and its arguments decide. |
| Persistence | T1543.003 Create or Modify System Process: Windows Service | C0015-R09 | alert | A service is installed whose binary lives in ProgramData, Public, Temp or AppData. | Some installers place services there; the service name and binary signature decide. |
| Impact | T1490 Inhibit System Recovery | C0015-R10 | alert | vssadmin or wmic deletes volume shadow copies. | Backup software also manages shadows; correlate with the note and the rename burst. |
| Exfiltration | T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage | C0015-R11 | alert | rclone copies or syncs data to a remote destination. | Exit code is not proof of transfer; there is no receiver inventory in endpoint telemetry. |
| Impact | T1486 Data Encrypted for Impact | C0015-R12 | alert | The Conti-style locker is started with its deployment flag set: mode, network, size and target path. | Keys on the documented argument shape of this family; a repacked locker with different flags is missed. |
| Persistence | T1543.003 Create or Modify System Process: Windows Service | C0015-R13 | building_block | A process started by the service manager lives in a user-writable directory. | Context for R09; not proof of persistence by itself. |

## Not covered by a rule

The lab exercises steps that no shipped rule detects: module download over HTTP, service
installation (System channel, provider Service Control Manager), the scheduled task used as a
foothold, and the transfer receipt at the cloud receiver. Those are listed here so the absence
is explicit rather than implied.
