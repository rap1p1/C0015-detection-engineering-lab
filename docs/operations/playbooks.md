# Investigation playbooks

## P1 - Document to loader (R01, R02, R03)

1. Confirm Sysmon 1 and 7 exist for the host and the window.
2. Resolve the alert's source events, then walk the parent chain: Word, cmd, mshta, regsvr32.
3. Check the module: unsigned, user-writable path.
4. Escalate when the chain reaches an unsigned module and the host is a workstation.
5. Close when the module is signed and the chain matches a known deployment.
6. Insufficient information when no ancestry is recorded: keep open, record the gap.

## P2 - Agent escalation and credential access (R04, R05)

1. Confirm the child process of `HealthMonitor.exe` and the script it ran.
2. Identify what the script wrote and where it downloaded from.
3. Confirm mimikatz execution and whether the target was LSASS or LSA secrets.
4. Escalate: a SYSTEM child of a monitoring agent is a privilege escalation, not a maintenance action.
5. Close only with a documented change ticket that explains the script.
6. Insufficient information when the agent log is unavailable; treat the absence as telemetry loss.

## P3 - Lateral movement, injection, exfiltration and impact (R06, R07, R08, R14, R15, R11, R12)

1. Confirm the network logon on the target, the Defender change and the WMI child process.
2. Confirm the remote thread into svchost (E8) and the module loaded from ProgramData (E7).
3. Confirm rclone execution and its command line; there is no receiver proof.
4. Escalate to incident response once a service or a note is confirmed.
5. Close only after the host is rebuilt and the corpus restored from baseline.
6. Insufficient information when the target-side events are unavailable; do not infer from source alone.
