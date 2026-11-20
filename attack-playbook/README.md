# Attack playbook

The manual run of the current chain. Read [`kill-chain/README.md`](../kill-chain/README.md) first; this
page is the operator view: what to set up once, what to run, what to check after every step.

## 0. One-time lab weaknesses (not part of the attack)

| Weakness | Where | Script |
|---|---|---|
| HealthMonitor agent runs `checks\*.ps1` as LocalSystem and the directory is writable by Users | WS01 | [`setup/install-healthmonitor.ps1`](setup/install-healthmonitor.ps1) |
| Backup service runs as `C0015\Administrator`, so its password sits in LSA secrets | WS01 | [`setup/create-backup-service.ps1`](setup/create-backup-service.ps1) |
| Defender real-time off, Tamper Protection off | WS01 | manual, image build |
| A data corpus and a MEGA remote | FS01 / Kali | existing lab data, [`tools/rclone`](../tools/rclone/README.md) |

## 1. Run

1. Start Sliver, the HTTPS listener and the HTTP staging server on Kali ([`tools/sliver`](../tools/sliver/README.md)).
2. Log in on WS01 as `duc.user`, open `decree-08.03.2021.docm` from the Desktop.
3. The chain runs: macro, HTA, regsvr32 loader, the loader writes `update.ps1` into the agent directory,
   HealthMonitor executes it as SYSTEM, the beacon starts.
4. On Kali, take the WS01 session and recover the administrator secret:
   `mimikatz.exe "privilege::debug" "lsadump::secrets" exit`.
5. Move to FS01: WMI with the recovered credential to disable Defender/ASR, then upload the beacon and
   install it as a service.
6. On the FS01 beacon, run `fs01-task.ps1` and follow its gate.

## 2. Step checks

| Step | Command | Pass when |
|---|---|---|
| Agent script executed | `Get-Content C:\ProgramData\HealthMonitor\agent.log -Tail 5` | a line for `update.ps1` |
| Beacon on WS01 | `sessions` on Kali | a session as `NT AUTHORITY\SYSTEM` |
| Administrator secret | mimikatz output | a `User Name : Administrator` block |
| Defender off on FS01 | `(Get-MpComputerStatus).RealTimeProtectionEnabled` | `False` |
| Beacon on FS01 | `sessions` | a session on FS01 |
| Service persistence | `sc query C0015Svc` | `RUNNING`, start type auto |
| Exfil | rclone exit code | `0`, no `ERROR` in the log |
| Impact | file counts | `readme.txt` present, `.c0015` files created |

## 3. Payloads

All payloads are in [`payloads/`](payloads/README.md), named after the phase they belong to.

## 4. Clean up

Stop and delete the service, delete the beacon files, restore the corpus from its baseline, remove the
planted checks, and leave the one-time weaknesses in place (they are lab infrastructure, not artefacts of
the run).
