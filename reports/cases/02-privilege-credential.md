# Case 02 - Agent escalation and the administrator secret

**Status:** evidence pending.

## Expected alerts

| Rule | What it should show |
|---|---|
| R04 agent child | `HealthMonitor.exe` (SYSTEM) starts `powershell.exe -File ...checks\update.ps1` |
| R05 mimikatz | `mimikatz.exe` with `privilege::debug` and `lsadump::secrets` |

## Investigation

0. Confirm the discovery commands from the SYSTEM context (R18): `net group "domain admins" /dom`, `net localgroup administrator`, `nltest /domain_trusts`, `net view /all /domain`.

1. Confirm the agent service runs as LocalSystem and that the checks directory is writable by Users.
2. Confirm the script was written by the loader (same host, minutes earlier) and executed by the agent.
3. Confirm the beacon started as SYSTEM.
4. Confirm mimikatz read LSA secrets and recovered `C0015\Administrator`.

## What the chain proves and does not

- Proves, by source: the loader wrote `update.ps1` into the checks directory (E11, `regsvr32.exe`), the
  agent log records the run, and the PowerShell E1 carries `user.name = SYSTEM` together with that script
  path. The command line shows that LSA secret extraction was requested with `lsadump::secrets`; the
  recovered value is recorded separately and redacted in the evidence.
- Does not prove: that the secret was used after extraction, or process ancestry from the agent to PowerShell - the E1 in this run has no parent populated,
  so the link comes from the service configuration and the agent log, not from the event graph. It also does
  not prove that LSASS was touched; `lsadump::secrets` is not `sekurlsa`, and an E10-only rule would not see it.

## Evidence to capture

- `agent.log` line for `update.ps1`, the E11 write of the script, the PowerShell E1 with `user.name = SYSTEM`, the mimikatz command line, and the recovered `_SC_C0015Backup` secret.

