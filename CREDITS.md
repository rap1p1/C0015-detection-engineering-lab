# Credits

## Source material

| Source | Used for |
|---|---|
| The DFIR Report, *CONTInuing the Bazar Ransomware Story*, 29 November 2021 - <https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/> | Campaign narrative, process ancestry, command lines, Cobalt Strike configuration, indicator set |
| MITRE ATT&CK campaign C0015 - <https://attack.mitre.org/campaigns/C0015/> | Technique identifiers used in the rules and in `docs/attack-coverage.md` |

The campaign description in this repository is a paraphrase of the source report. No sentence is
quoted verbatim.

## Tooling

| Tool | Role in the lab | Licence |
|---|---|---|
| Sliver (BishopFox) - <https://github.com/BishopFox/sliver> | C2 framework, implant generation, migration, SOCKS proxy | GPL-3.0 |
| Sysmon (Microsoft Sysinternals) - <https://learn.microsoft.com/sysinternals/downloads/sysmon> | Endpoint telemetry | Proprietary, free |
| Elastic Security - <https://www.elastic.co/security> | Ingestion and rule evaluation | Elastic Licence |
| rclone - <https://rclone.org/> | Exfiltration stage | MIT |
| Process Hacker - <https://processhacker.sourceforge.io/> | LSASS access and dump | GPL-3.0 |
| Mimikatz (Benjamin Delpy) - <https://github.com/gentilkiwi/mimikatz> | Offline parsing of the dump | CC BY 4.0 |
| PowerView (PowerSploit) - <https://github.com/PowerShellMafia/PowerSploit> | Share enumeration | BSD-3-Clause |
| AnyDesk - <https://anydesk.com/> | Portable remote access stage | Proprietary, free for personal use |
| mingw-w64 - <https://www.mingw-w64.org/> | Building the service stub and the locker simulator | ZPL / MIT |

## Lab components

The service stub, the HTA, the macro module, the locker simulator, the detection rules, the nginx
front, and the provisioning scripts are original work for this lab and are covered by the repository
licence.
