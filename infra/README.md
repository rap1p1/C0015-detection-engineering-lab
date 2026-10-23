# Lab infrastructure

Three Windows hosts and one Linux host on a host-only segment. The domain controller provides DNS for
the lab zone, which is also how the campaign domain names are resolved without leaving the network.

| Host | Address | Role | Notes |
|---|---|---|---|
| DC01 | 192.168.50.10 | AD DS and DNS for `c0015.lab` | No operator interaction during the run |
| WS01 | 192.168.50.20 | Initial workstation, victim host | 4 GB RAM, Windows 10 |
| FS01 | 192.168.50.30 | Backup server, lateral target | Backup shares, corpus, second beacon, impact origin |
| KALI | 192.168.50.100 | C2, staging, network tooling | Sliver server, nginx front, proxy client |
| WIN-C2 | 192.168.50.1 | HTTP staging and operator tooling | Serves the module, HTA, and PowerView |

Network: VMware VMnet2, `192.168.50.0/24`, DHCP disabled. WS01 and FS01 also carry a NAT adapter for
operating-system updates. The lab segment has no route to the internet; outbound lookups for campaign
names resolve inside the zone or fail.

## Layout

| Path | Contents |
|---|---|
| `sysmon/` | Sysmon configuration profiles used on the Windows hosts |
| `dns/` | Zone design for the campaign hostnames |
| `c2/` | Listener layout, nginx front, implant generation commands |
| `scripts/` | Provisioning scripts for accounts, shares, and DNS |

## Sequence

1. Apply `sysmon/sysmon-c0015-balanced.xml` to WS01 and FS01 and confirm events 1, 3, 7, 8, 10, 11, and 22.
2. Create the accounts and shares described in [`accounts.md`](accounts.md).
3. Apply the DNS zones in [`dns/zone-plan.md`](dns/zone-plan.md) on DC01.
4. Start the listeners per [`c2/README.md`](c2/README.md) and verify name resolution from WS01.
5. Take a snapshot of all three hosts before the first run.

## Accounts and DNS

The account model and its rationale are in [`accounts.md`](accounts.md). The zone design and the
records that must be absent are in [`dns/zone-plan.md`](dns/zone-plan.md).
