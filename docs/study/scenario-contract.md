# Scenario contract

## One-time setup (image build, not part of the attack)

| Step | Script | Result |
|---|---|---|
| Agent weakness | [`attack-playbook/setup/install-healthmonitor.ps1`](../../attack-playbook/setup/install-healthmonitor.ps1) | service `HealthMonitor` as LocalSystem, `checks` writable by Users |
| Backup service | [`attack-playbook/setup/create-backup-service.ps1`](../../attack-playbook/setup/create-backup-service.ps1) | task runs as `C0015\Administrator`; password in LSA secrets |
| Defender | manual | WS01 real-time off, Tamper Protection off |
| Corpus | existing lab data | `C:\C0015\corpus` with baseline inventory |

## Per-run order

1. Kali: Sliver daemon, HTTPS listener 443, HTTP staging 80.
2. WS01: log in as `duc.user`, confirm the document on the Desktop.
3. Open the document. The chain runs to the SYSTEM beacon without further operator action.
4. Kali: `sessions`, then mimikatz `lsadump::secrets` on the WS01 beacon.
5. WMI with `C0015\Administrator`: disable Defender on FS01, verify, upload the beacon, install the service.
6. On the FS01 beacon: run `fs01-task.ps1`; each step verifies before the next.
7. Capture the alerts and events, then clean up.

## Checks after each step

| Step | Check | Expected |
|---|---|---|
| agent script | `agent.log` on WS01 | line for `update.ps1` |
| beacon WS01 | Sliver `sessions` | session as SYSTEM |
| credential | mimikatz output | `Administrator` secret recovered |
| Defender FS01 | `Get-MpComputerStatus` | `RealTimeProtectionEnabled : False` |
| service | `sc query C0015Svc` | `RUNNING`, auto start |
| exfil | rclone exit code | `0` |
| impact | corpus counts | `readme.txt` present, `.c0015` files created |
