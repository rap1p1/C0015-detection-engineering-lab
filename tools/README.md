# Attack tools

Tooling used by the scenario. Each folder documents the version, how it is obtained, the exact command
used in the chain and the telemetry it leaves behind.

| Tool | Folder | Used in phase | Notes |
|---|---|---|---|
| Mimikatz | [`mimikatz/`](mimikatz/README.md) | credential access | reads LSA secrets of the maintenance task |
| Sliver | [`sliver/`](sliver/README.md) | beacon on WS01 and FS01 | HTTPS listener 443, `persist` not available in this build |
| rclone | [`rclone/`](rclone/README.md) | exfiltration | config with the MEGA remote, uploaded at run time |
| Impacket | [`impacket/`](impacket/README.md) | lateral movement | `wmiexec`/`psexec` with `-hashes` |
| PsExec | [`psexec/`](psexec/README.md) | lateral movement alternative | service-based, leaves 7045 |
| vssadmin | [`vssadmin/`](vssadmin/README.md) | impact | shadow copy deletion |
| certutil | [`certutil/`](certutil/README.md) | delivery | download cradle for the beacon |

Rules for this folder:

- no credentials, tokens or private keys;
- binaries only when their licence allows redistribution, otherwise a pinned download instruction and hash;
- every file states which phase uses it, so the kill chain stays traceable.
