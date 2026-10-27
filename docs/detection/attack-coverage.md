# ATT&CK coverage

Generated from [`detections/catalog.json`](../../detections/catalog.json) by
`tools/detections/catalog.py --coverage`. It records what each rule observes, not what the
campaign achieved.

| Tactic | Technique | Rule | Role | What the rule observes | Limitation |
|---|---|---|---|---|---|
| Execution | T1204.002 User Execution: Malicious File | C0015-R01 | building_block | An Office process starts a shell or script host. Single event, so a long-running Office parent still matches. | Benign macros and document add-ins produce the same edge; treat as context for the loader rule, not as proof of execution. |
| Defense Evasion | T1218.005 System Binary Proxy Execution: Mshta | C0015-R02 | building_block | A script host starts regsvr32 or rundll32. | Observation only; the loader behaviour is carried by C0015-R03. |
| Defense Evasion | T1574 Hijack Execution Flow | C0015-R03 | alert | rundll32 or regsvr32 loads an unsigned module from a staging directory. Judged on the module event itself, so a loader that was created long before still matches. | Unsigned module load is not evidence of C2 or injection; the staging path list is the scope. |
| Privilege Escalation | T1055 Process Injection | C0015-R04 | alert | A loader or interpreter creates a remote thread in winlogon, lsass, services or a service host. | One thread-creation event does not prove the payload executes; the target instance and start address are context. |
| Credential Access | T1003.001 LSASS Memory | C0015-R05 | alert | A process opens LSASS with a dump-like access mask. Known system processes under the system directories and the Elastic agent paths are excluded. | Access is not extraction. A process that opens LSASS may be a diagnostic tool; masks outside the list are not covered. The exclusions combine a path and a name, so a similarly named binary outside those paths is still reported. |
| Lateral Movement | T1047 Windows Management Instrumentation | C0015-R06 | building_block | wmic is invoked with a remote node and a process creation verb. | Source intent only; the return value and the target-side execution are separate observations. |
| Lateral Movement | T1047 Windows Management Instrumentation | C0015-R07 | alert | WmiPrvSE starts rundll32 or regsvr32 on the target. | A loader under WMI is specific; generic shells under WMI are covered by C0015-R18. |
| Defense Evasion | T1218.011 System Binary Proxy Execution: Rundll32 | C0015-R08 | building_block | A service host starts a loader from a staging path. | Parent-child observation only; it does not prove a service was created or modified. |
| Exfiltration | T1567.002 Exfiltration to Cloud Storage | C0015-R11 | alert | rclone runs a copy or sync verb against a remote whose name contains mega. | Intent only. The remote alias is not proof the destination is MEGA, and no transfer volume is observed. |
| Impact | T1486 Data Encrypted for Impact | C0015-R12 | building_block | A file named readme.txt is created. | A single note is not impact. Fanout across directories is the analyst signal; a legitimate README matches too. |
| Lateral Movement | T1021.001 Remote Services: Remote Desktop Protocol | C0015-R13 | enrichment | A non-machine account opens an interactive RDP session. | Context only. Type 10 does not prove a tunnel or malicious intent. |
| Credential Access | T1110 Brute Force | C0015-R15 | alert | Three failed network logons for one account on one host followed by a successful network logon. | The lab tests several passwords for one account: that is credential guessing, not spraying across many accounts. The failure reason is not filtered, and the count is scoped to a host and an account. |
| Defense Evasion | T1562.001 Impair Defenses: Disable or Modify Tools | C0015-R16 | alert | The RunAsPPL registry value is written to zero. | Configuration change only; effective protection also depends on reboot or policy. |
| Discovery | T1087 Account Discovery | C0015-R17 | building_block | A shell spawned by a logon process, loader or service host runs one discovery command with campaign-style arguments. | One command is context, not a burst: there is no threshold or grouping here. A separate correlation would be needed to call it a burst. |
| Lateral Movement | T1047 Windows Management Instrumentation | C0015-R18 | building_block | WmiPrvSE starts a generic shell or interpreter. | Administrative WMI does the same; kept as context for the loader rule. |

## Not covered by a rule

The lab exercises steps that no shipped rule detects: module download over HTTP, service
installation (System channel, provider Service Control Manager), the scheduled task used as a
foothold, and the transfer receipt at the cloud receiver. Those are listed here so the absence
is explicit rather than implied.
