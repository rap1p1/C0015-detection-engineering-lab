# Case 02 - Agent escalation and the administrator secret

**Status:** evidence pending.

## Expected alerts

| Rule | What it should show |
|---|---|
| R22 (planned) agent child | `HealthMonitor.exe` (SYSTEM) starts `powershell.exe -File ...checks\update.ps1` |
| R23 (planned) mimikatz | `mimikatz.exe` with `privilege::debug` and `lsadump::secrets` |

## Investigation

1. Confirm the agent service runs as LocalSystem and that the checks directory is writable by Users.
2. Confirm the script was written by the loader (same host, minutes earlier) and executed by the agent.
3. Confirm the beacon started as SYSTEM.
4. Confirm mimikatz read LSA secrets and recovered `C0015\Administrator`.

## What the chain proves and does not

- Proves: a standard user reached SYSTEM through a misconfigured agent, then read a stored administrator
  secret.
- Does not prove: that the administrator logged on to WS01, or that LSASS was touched. `lsadump::secrets`
  is not `sekurlsa`, so an E10-only rule will not see it.

## Evidence to capture

- `agent.log` line for `update.ps1`, the SYSTEM child process event, the mimikatz command line.
