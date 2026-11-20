# Detection index

Generated from [`catalog.json`](catalog.json) by `tools/detections/catalog.py`. Do not edit.

- shipped rules: **17**
- retired rules: **1**
- roles: alert 15, building_block 2

| ID | Rule | Role | Severity | ATT&CK | Query |
|---|---|---|---|---|---|
| C0015-R01 | office spawns script host | alert | medium | T1204.002 User Execution: Malicious File | [`01-office-spawns-script-host.eql`](eql/01-office-spawns-script-host.eql) |
| C0015-R02 | script host starts loader | alert | high | T1218.010 System Binary Proxy Execution: Regsvr32 | [`02-script-host-starts-loader.eql`](eql/02-script-host-starts-loader.eql) |
| C0015-R03 | loader loads untrusted module | alert | high | T1218.010 System Binary Proxy Execution: Regsvr32 | [`03-loader-loads-unsigned-module.eql`](eql/03-loader-loads-unsigned-module.eql) |
| C0015-R04 | agent executes planted script | alert | medium | T1059.001 Command and Scripting Interpreter: PowerShell | [`04-agent-executes-script.eql`](eql/04-agent-executes-script.eql) |
| C0015-R05 | LSA secrets requested | alert | high | T1003.004 OS Credential Dumping: LSA Secrets | [`05-credential-tool-lsa-secrets.eql`](eql/05-credential-tool-lsa-secrets.eql) |
| C0015-R06 | defender real-time protection disable requested | alert | high | T1562.001 Impair Defenses: Disable or Modify Tools | [`06-defender-settings-weakened.eql`](eql/06-defender-settings-weakened.eql) |
| C0015-R07 | wmi remote process creation | alert | high | T1047 Windows Management Instrumentation | [`07-wmi-remote-execution-source.eql`](eql/07-wmi-remote-execution-source.eql) |
| C0015-R08 | wmi hosted child process | building_block | medium | T1047 Windows Management Instrumentation | [`08-wmi-hosted-child-process.eql`](eql/08-wmi-hosted-child-process.eql) |
| C0015-R10 | shadow copy deletion requested | alert | high | T1490 Inhibit System Recovery | [`10-shadow-copy-deletion.eql`](eql/10-shadow-copy-deletion.eql) |
| C0015-R11 | rclone transfer invocation | alert | high | T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage | [`11-cloud-transfer.eql`](eql/11-cloud-transfer.eql) |
| C0015-R12 | locker simulator invocation | alert | high | T1486 Data Encrypted for Impact | [`12-locker-invocation.eql`](eql/12-locker-invocation.eql) |
| C0015-R13 | script written into agent checks | alert | high | T1574.010 Hijack Execution Flow: Services File Permissions Weakness | [`13-agent-checks-write.eql`](eql/13-agent-checks-write.eql) |
| C0015-R14 | remote thread into service host | alert | high | T1055 Process Injection | [`14-injection-into-svchost.eql`](eql/14-injection-into-svchost.eql) |
| C0015-R15 | module loaded from user path | building_block | low | T1574 Hijack Execution Flow | [`15-module-from-user-path.eql`](eql/15-module-from-user-path.eql) |
| C0015-R16 | dns query for campaign domain | alert | medium | T1071.004 Application Layer Protocol: DNS | [`16-dns-query-campaign-domain.eql`](eql/16-dns-query-campaign-domain.eql) |
| C0015-R17 | dns lookup then beacon connection | alert | high | T1071.001 Application Layer Protocol: Web Protocols | [`17-dns-then-beacon-connection.eql`](eql/17-dns-then-beacon-connection.eql) |
| C0015-R18 | domain and trust discovery | alert | medium | T1087.002 Account Discovery: Domain Account | [`18-discovery-commands.eql`](eql/18-discovery-commands.eql) |

## Retired

| ID | Rule | Reason |
|---|---|---|
| C0015-R09 | service installed from user path | The injection chain does not install a service; the rule has no subject. |
