# Detection index

Generated from [`catalog.json`](catalog.json) by `tools/detections/catalog.py`. Do not edit.

- shipped rules: **15**
- retired rules: **2**
- roles: alert 7, building_block 7, enrichment 1

| ID | Rule | Role | Severity | ATT&CK | Query |
|---|---|---|---|---|---|
| C0015-R01 | office spawns script host | building_block | medium |  | [`01-office-spawns-script-host.eql`](eql/01-office-spawns-script-host.eql) |
| C0015-R02 | script host starts loader | building_block | medium |  | [`02-script-host-starts-loader.eql`](eql/02-script-host-starts-loader.eql) |
| C0015-R03 | loader loads unsigned module | alert | high |  | [`03-loader-loads-unsigned-module.eql`](eql/03-loader-loads-unsigned-module.eql) |
| C0015-R04 | injection into system process | alert | high |  | [`04-injection-into-system-process.eql`](eql/04-injection-into-system-process.eql) |
| C0015-R05 | lsass credential access | alert | high |  | [`05-lsass-credential-access.eql`](eql/05-lsass-credential-access.eql) |
| C0015-R06 | wmi remote creation | building_block | low |  | [`06-wmi-remote-creation.eql`](eql/06-wmi-remote-creation.eql) |
| C0015-R07 | wmi loader execution | alert | high |  | [`07-wmi-hosted-loader.eql`](eql/07-wmi-hosted-loader.eql) |
| C0015-R08 | service host starts loader | building_block | low |  | [`08-service-host-starts-loader.eql`](eql/08-service-host-starts-loader.eql) |
| C0015-R11 | rclone transfer intent | alert | medium |  | [`11-cloud-transfer.eql`](eql/11-cloud-transfer.eql) |
| C0015-R12 | note creation | building_block | low |  | [`12-ransom-note.eql`](eql/12-ransom-note.eql) |
| C0015-R13 | rdp interactive logon | enrichment | low |  | [`13-rdp-interactive-logon.eql`](eql/13-rdp-interactive-logon.eql) |
| C0015-R15 | repeated authentication failures then success | alert | high |  | [`15-password-spray.eql`](eql/15-password-spray.eql) |
| C0015-R16 | lsass protection removed | alert | medium |  | [`16-lsass-protection-removed.eql`](eql/16-lsass-protection-removed.eql) |
| C0015-R17 | discovery command | building_block | low |  | [`17-discovery-command.eql`](eql/17-discovery-command.eql) |
| C0015-R18 | wmi shell execution | building_block | medium |  | [`18-wmi-shell.eql`](eql/18-wmi-shell.eql) |

## Retired

| ID | Rule | Reason |
|---|---|---|
| C0015-R09 | ntlm logon with privileges | EQL can join per clause, but the pair does not prove pass-the-hash and the single-event form matches every NTLM network logon in a domain. |
| C0015-R14 | task manager from shell | Task Manager started with /4 is operator habit, reachable by any user and does not justify a visible alert; kept as a saved hunt note. |
