# Case 01 - Document to loader

**Status:** evidence pending. The chain was rebuilt in November 2026 and has not been captured yet; this
page records the expected evidence and the questions the capture must answer.

## Expected alerts

| Rule | What it should show |
|---|---|
| R01 office spawns script host | `WINWORD.EXE` -> `cmd.exe /c mshta ...` on WS01 as `duc.user` |
| R02 script host starts loader | `mshta.exe` -> `regsvr32.exe C:\Users\Public\compareForfor.jpg` |
| R03 loader loads untrusted module | Sysmon 7 for that `.jpg`, signed false, same process entity |

## Investigation

R02 records the invocation of `regsvr32`; R03 records that a module was actually loaded. They are two observations of the same step, not duplicates.

1. Resolve the source event of the R03 alert and confirm the loading process is the `regsvr32` from R02.
2. Walk the parent chain by entity id: regsvr32 -> mshta -> cmd -> Word.
3. Confirm the module is untrusted and lives in a user-writable path.
4. Look for the loader's write into `C:\ProgramData\HealthMonitor\checks` (Sysmon 11).

## What the chain proves and does not

- Proves: a document started a shell, which started `mshta`, which started `regsvr32`, which loaded an
  untrusted module and dropped a script.
- Does not prove: that the module executed, that the script ran, or that the agent executed it.

## Evidence to capture

- R01/R02/R03 alert screenshots and the process-creation table with entity ids.
- The Sysmon 11 write of `update.ps1` into the checks directory.
