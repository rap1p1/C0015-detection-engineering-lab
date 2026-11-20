# Architecture

| Host | Address | Role | OS |
|---|---|---|---|
| DC01 | 192.168.50.10 | AD DS, DNS for `c0015.lab` | Windows Server 2019 |
| WS01 | 192.168.50.20 | victim workstation, initial foothold | Windows 10 22H2 |
| FS01 | 192.168.50.30 | file server, lateral target, impact origin | Windows 10 22H2 |
| Kali | 192.168.50.100 | C2, staging, operator host | Kali |

Network: VMnet2 `192.168.50.0/24`, no DHCP. WS01 and FS01 carry a second NAT adapter so the lab can pull
updates and reach the cloud remote; that adapter is the only egress path.

## Accounts

| Account | Type | Rights used |
|---|---|---|
| `C0015\duc.user` | domain user (standard) | opens the document, runs the loader; no local admin |
| `C0015\Administrator` | domain administrator (RID 500) | recovered from LSA secrets, then used for WMI |
| `NT AUTHORITY\SYSTEM` | local system | agent child, beacon, service, impact |

No `helpdesk`, no `IT-Support`, no `it.admin`, no `bk.admin`.

## Services and weaknesses

| Component | Runs as | Weakness |
|---|---|---|
| `HealthMonitor` | LocalSystem | executes every `C:\ProgramData\HealthMonitor\checks\*.ps1`; that directory is writable by Users |
| `C0015Maintenance` scheduled task | `C0015\Administrator` | the password is stored in LSA secrets, readable by SYSTEM |
| Defender on WS01 | - | real-time protection off, Tamper Protection off (lab precondition) |

## Telemetry path

Sysmon (1, 3, 7, 8, 10, 11, 13) and the Security channel ship through Elastic Agent to Elasticsearch;
Kibana is the analysis surface. Data views: `logs-windows.sysmon_operational-*`,
`logs-system.security-*`; alerts live in `.internal.alerts-security.alerts-default*`.
