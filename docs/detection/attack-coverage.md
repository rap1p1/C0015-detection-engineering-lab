# ATT&CK coverage

Generated from [`detections/catalog.json`](../../detections/catalog.json) by
`tools/detections/catalog.py --coverage`. It records what each rule observes, not what the
campaign achieved.

| Tactic | Technique | Rule | Role | What the rule observes | Limitation |
|---|---|---|---|---|---|
| Execution | T1204.002 User Execution: Malicious File | C0015-R01 | alert | An Office process starts a shell or script host from a document. | Benign macros and add-ins produce the same edge; correlate with the loader that follows. |
| Defense Evasion | T1218.010 System Binary Proxy Execution: Regsvr32 | C0015-R02 | alert | mshta, cmd or wscript starts regsvr32 on a file in a user-writable path or with a non-DLL extension. | regsvr32 is also used by installers; the path and extension carry most of the signal. |
| Defense Evasion | T1218.010 System Binary Proxy Execution: Regsvr32 | C0015-R03 | alert | regsvr32 loads a module whose signature is not trusted, from a user-writable path or an image extension. | The field is a trust verdict, not a signature check; in-house modules without a signature match as well. |
| Execution | T1059.001 Command and Scripting Interpreter: PowerShell | C0015-R04 | alert | PowerShell runs a .ps1 from the agent checks directory, the directory the service executes from. | A legitimate health check can run the same command; correlate with the file write and the account. |
| Credential Access | T1003.004 OS Credential Dumping: LSA Secrets | C0015-R05 | alert | A command line asks mimikatz for LSA secrets. | String match: a renamed tool that assembles the argument at runtime is missed; the string can appear as data. |
| Defense Evasion | T1562.001 Impair Defenses: Disable or Modify Tools | C0015-R06 | alert | PowerShell disables Defender real-time protection with Set-MpPreference. | A maintenance window produces the same event; the approval and the host role decide. |
| Execution | T1047 Windows Management Instrumentation | C0015-R07 | alert | wmic is asked to create a process on another host; `/node:` is required, `/user:` and `/password:` are enrichment. | Source-side only; the command line carries the credential and must be redacted in evidence. |
| Execution | T1047 Windows Management Instrumentation | C0015-R08 | building_block | The WMI provider host starts a shell or script host; context for the action, not an alert on its own. | Management tooling creates processes through WMI; treat as context, not as proof of intent. |
| Impact | T1490 Inhibit System Recovery | C0015-R10 | alert | vssadmin or wmic is asked to delete volume shadow copies. | The event is the request, not the result; backup software also manages shadows. |
| Exfiltration | T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage | C0015-R11 | alert | rclone copies or syncs data to a remote destination. | Matches the transfer subcommand in the command line; the direction (local copy, upload, download) is not proven by E1 alone. |
| Impact | T1486 Data Encrypted for Impact | C0015-R12 | alert | The Conti-style locker is started with its deployment flag set. | Keys on this family argument shape and on the simulator name; a repacked locker is missed. |
| Persistence | T1574.010 Hijack Execution Flow: Services File Permissions Weakness | C0015-R13 | alert | regsvr32 writes a .ps1 into the directory the HealthMonitor service executes as LocalSystem. | Bounded to the documented writer; another process planting a script in the same directory is not covered. |
| Defense Evasion | T1055 Process Injection | C0015-R14 | alert | rundll32 creates a remote thread inside a svchost process. | Legitimate instrumentation and accessibility tools also create remote threads; the source image and the module loaded decide. |
| Defense Evasion | T1574 Hijack Execution Flow | C0015-R15 | building_block | A module is loaded from the staging directory; the loading process decides which behaviour this is. | The directory is lab-specific; in a real estate the rule needs the writable path that the service uses. |

## Not covered by a rule

The lab exercises steps that no shipped rule detects: module download over HTTP, service
installation (System channel, provider Service Control Manager), the scheduled task used as a
foothold, and the transfer receipt at the cloud receiver. Those are listed here so the absence
is explicit rather than implied.
