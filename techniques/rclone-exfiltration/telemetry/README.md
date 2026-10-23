# Expected telemetry - rclone exfiltration to MEGA

rclone copies shares to a MEGA remote with bandwidth and parallelism limits, twice, with an RDP session between the rounds.

| Source | Event | Fields |
|---|---|---|
| Sysmon E1 | `rclone.exe copy --max-age 2y ... Mega:DATA` | `process.command_line` |
| Sysmon E3 | egress to the MEGA API endpoints | `destination.ip`, `destination.port`, `destination.domain` |
| Security 5145 | source share reads before the transfer | `ShareName`, `AccessMask` |

Collection notes: Sysmon 15.x with the profile in `infra/sysmon/`; Security channel with process
creation auditing and command-line inclusion; PowerShell script block logging for the enumeration
step. Field names in the rules assume the Elastic Common Schema mapping produced by the Elastic
Agent Windows integration.
