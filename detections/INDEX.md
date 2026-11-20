# Detection index

Generated from [`catalog.json`](catalog.json) by `tools/detections/catalog.py`. Do not edit.

- shipped rules: **12**
- retired rules: **0**
- roles: alert 12

| ID | Rule | Role | Severity | ATT&CK | Query |
|---|---|---|---|---|---|
| C0015-R01 | office spawns script host | alert | medium | T1204.002 User Execution: Malicious File | [`01-office-spawns-script-host.eql`](eql/01-office-spawns-script-host.eql) |
| C0015-R02 | script host starts loader | alert | high | T1218.010 System Binary Proxy Execution: Regsvr32 | [`02-script-host-starts-loader.eql`](eql/02-script-host-starts-loader.eql) |
| C0015-R03 | loader loads unsigned module | alert | high | T1218.010 System Binary Proxy Execution: Regsvr32 | [`03-loader-loads-unsigned-module.eql`](eql/03-loader-loads-unsigned-module.eql) |
| C0015-R04 | agent executes planted script | alert | high | T1059.001 Command and Scripting Interpreter: PowerShell | [`04-agent-executes-script.eql`](eql/04-agent-executes-script.eql) |
| C0015-R05 | credential tool reads LSA secrets | alert | critical | T1003.004 OS Credential Dumping: LSA Secrets | [`05-credential-tool-lsa-secrets.eql`](eql/05-credential-tool-lsa-secrets.eql) |
| C0015-R06 | defender settings weakened | alert | high | T1562.001 Impair Defenses: Disable or Modify Tools | [`06-defender-settings-weakened.eql`](eql/06-defender-settings-weakened.eql) |
| C0015-R07 | wmi remote process creation | alert | high | T1047 Windows Management Instrumentation | [`07-wmi-remote-execution-source.eql`](eql/07-wmi-remote-execution-source.eql) |
| C0015-R08 | wmi hosted child process | alert | high | T1047 Windows Management Instrumentation | [`08-wmi-hosted-child-process.eql`](eql/08-wmi-hosted-child-process.eql) |
| C0015-R09 | service installed from user path | alert | high | T1543.003 Create or Modify System Process: Windows Service | [`09-service-install-user-path.eql`](eql/09-service-install-user-path.eql) |
| C0015-R10 | shadow copies deleted | alert | high | T1490 Inhibit System Recovery | [`10-shadow-copy-deletion.eql`](eql/10-shadow-copy-deletion.eql) |
| C0015-R11 | cloud transfer with rclone | alert | high | T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage | [`11-cloud-transfer.eql`](eql/11-cloud-transfer.eql) |
| C0015-R12 | locker command line | alert | critical | T1486 Data Encrypted for Impact | [`12-ransom-note.eql`](eql/12-ransom-note.eql) |
