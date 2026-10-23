# Topology

## Hosts

| Host | Address | Role | Operating system |
|---|---|---|---|
| DC01 | 192.168.50.10 | AD DS, DNS for `c0015.lab` | Windows Server 2019 |
| WS01 | 192.168.50.20 | Victim workstation, initial foothold | Windows 10 22H2 |
| FS01 | 192.168.50.30 | Backup server, lateral target, impact origin | Windows 10 22H2 |
| KALI | 192.168.50.100 | C2 server, staging, network tooling | Kali Linux |
| WIN-C2 | 192.168.50.1 | HTTP staging for module and PowerView | Windows host or lab hypervisor |

FS01 holds the backup shares and the corpus used for collection and impact. The campaign separates the
backup server from the data server; the lab consolidates both roles on FS01 because the estate has a
single server, and the transfer command, the remote name, and the destination service are unchanged.

## Network

VMnet2, `192.168.50.0/24`, DHCP disabled. WS01 and FS01 carry a second NAT adapter for updates. During
a run there is no route from the lab segment to the internet, and DNS on DC01 has no forwarders.

## Telemetry path

```
WS01 / FS01
  Sysmon 15.x  ─┐
  Security log ─┼─> Elastic Agent ─> Fleet ─> Elasticsearch ─> detection rules ─> alerts
  PowerShell   ─┘
```

Sysmon profile: `infra/sysmon/sysmon-c0015-balanced.xml`. It logs process creation, network
connections, module loads from staging paths, cross-process thread creation, process access against
`lsass.exe` and `winlogon.exe`, file creation, DNS queries, and registry writes to service keys.
Events 23, 24, 27, and 28 are disabled because they either archive deleted files or block execution.

Security auditing: process creation with command line, logon and logoff, special privileges, explicit
credential use, and detailed file share access.

PowerShell: script block logging is enabled so the enumeration command is recoverable even when the
command line is truncated.

## Accounts

| Account | Scope | Purpose |
|---|---|---|
| `C0015\duc.user` | Local administrator on WS01 | Interactive victim |
| `C0015\bk.admin` | Local administrator on FS01 | Backup server administrator, pivot identity |
| `C0015\it.admin` | Domain administrator | Lab administration only |
| `C0015\svc_backup` | Service logon on FS01 | Backup agent identity |
| `C0015\WS01$` | Local administrator on FS01 | Machine account path for the SYSTEM pivot |

Rationale and provisioning: [`infra/accounts.md`](../infra/accounts.md).

## Domain services

DC01 publishes the zones that resolve the campaign hostnames to the C2 host, and deliberately does not
publish the fallback name. Design and verification queries: [`infra/dns/zone-plan.md`](../infra/dns/zone-plan.md).
