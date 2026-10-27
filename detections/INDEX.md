# Detection index

Generated from [`catalog.json`](catalog.json) by `tools/detections/catalog.py`. Do not edit.

- shipped rules: **15**
- retired rules: **2**
- roles: alert 7, building_block 7, enrichment 1

| ID | Rule | Role | Severity | ATT&CK | Query |
|---|---|---|---|---|---|
| C0015-R01 | office spawns script host | building_block | medium | T1204.002 User Execution: Malicious File | [`01-office-spawns-script-host.eql`](eql/01-office-spawns-script-host.eql) |
| C0015-R02 | script host starts loader | building_block | medium | T1218.005 System Binary Proxy Execution: Mshta | [`02-script-host-starts-loader.eql`](eql/02-script-host-starts-loader.eql) |
| C0015-R03 | loader loads unsigned module | alert | high | T1574 Hijack Execution Flow | [`03-loader-loads-unsigned-module.eql`](eql/03-loader-loads-unsigned-module.eql) |
| C0015-R04 | injection into system process | alert | high | T1055 Process Injection | [`04-injection-into-system-process.eql`](eql/04-injection-into-system-process.eql) |
| C0015-R05 | lsass credential access | alert | high | T1003.001 LSASS Memory | [`05-lsass-credential-access.eql`](eql/05-lsass-credential-access.eql) |
| C0015-R06 | wmi remote creation | building_block | low | T1047 Windows Management Instrumentation | [`06-wmi-remote-creation.eql`](eql/06-wmi-remote-creation.eql) |
| C0015-R07 | wmi loader execution | alert | high | T1047 Windows Management Instrumentation | [`07-wmi-hosted-loader.eql`](eql/07-wmi-hosted-loader.eql) |
| C0015-R08 | service host starts loader | building_block | low | T1218.011 System Binary Proxy Execution: Rundll32 | [`08-service-host-starts-loader.eql`](eql/08-service-host-starts-loader.eql) |
| C0015-R11 | rclone transfer intent | alert | medium | T1567.002 Exfiltration to Cloud Storage | [`11-cloud-transfer.eql`](eql/11-cloud-transfer.eql) |
| C0015-R12 | note creation | building_block | low | T1486 Data Encrypted for Impact | [`12-ransom-note.eql`](eql/12-ransom-note.eql) |
| C0015-R13 | rdp interactive logon | enrichment | low | T1021.001 Remote Services: Remote Desktop Protocol | [`13-rdp-interactive-logon.eql`](eql/13-rdp-interactive-logon.eql) |
| C0015-R15 | repeated authentication failures then success | alert | high | T1110 Brute Force | [`15-password-spray.eql`](eql/15-password-spray.eql) |
| C0015-R16 | lsass protection removed | alert | medium | T1562.001 Impair Defenses: Disable or Modify Tools | [`16-lsass-protection-removed.eql`](eql/16-lsass-protection-removed.eql) |
| C0015-R17 | discovery command | building_block | low | T1087 Account Discovery | [`17-discovery-command.eql`](eql/17-discovery-command.eql) |
| C0015-R18 | wmi shell execution | building_block | medium | T1047 Windows Management Instrumentation | [`18-wmi-shell.eql`](eql/18-wmi-shell.eql) |

## Retired

| ID | Rule | Reason |
|---|---|---|
| C0015-R09 | ntlm logon with privileges | EQL can join per clause, but the pair does not prove pass-the-hash and the single-event form matches every NTLM network logon in a domain. |
| C0015-R14 | task manager from shell | Task Manager started with /4 is operator habit, reachable by any user and does not justify a visible alert; kept as a saved hunt note. |
