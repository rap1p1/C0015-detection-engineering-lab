# Credits and references

## Source campaign

- MITRE ATT&CK campaign C0015, BazarLoader to Conti: <https://attack.mitre.org/campaigns/C0015/>
- The DFIR Report, "Continuing the Bazar ransomware story", 29 November 2021:
  <https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/>

## Tools used in the lab

| Tool | Link | Licence | Used for |
|---|---|---|---|
| Mimikatz | <https://github.com/gentilkiwi/mimikatz> | CC-BY-4.0 | LSA secrets |
| Sliver | <https://github.com/BishopFox/sliver> | GPL-3.0 | C2 beacon |
| rclone | <https://rclone.org/> | MIT | exfiltration |
| Impacket | <https://github.com/fortra/impacket> | Apache-2.0 | WMI/PsExec with a hash |
| PsExec (Sysinternals) | <https://learn.microsoft.com/sysinternals/> | Microsoft EULA | lateral movement alternative |
| Sysmon | <https://learn.microsoft.com/sysinternals/downloads/sysmon> | Microsoft EULA | endpoint telemetry |

## Prior art for the rules

See [`docs/detection/sigma-reference.md`](docs/detection/sigma-reference.md).
