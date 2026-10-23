# DNS zone design

The campaign names are resolved by DC01 instead of the internet. Two records exist so the implants can
reach the lab listeners under the campaign hostnames, and one record must not exist so the fallback
beacon fails the way it did in the original intrusion.

## Zones to create

| Zone | Record | Value | Purpose |
|---|---|---|---|
| `azureedge.net` | `five` A | 192.168.50.100 | Primary C2 hostname for the beacon |
| `checkauj.com` | `@` A | 192.168.50.100 | C2 hostname, matches the certificate subject |
| `checkauj.com` | `www` A | 192.168.50.100 | Present on the certificate as a subject alternative name |
| `millscruelg.com` | `@` A | 192.168.50.100 | Module download host for the HTA |
| `perdefue.fr` | `@` A | 192.168.50.100 | Name on the loader certificate |

## Record that must be absent

`volga.azureedge.net` is deliberately not created. The lookup returns a non-existent name, which is
what the report records for the fallback beacon: repeated queries, no connection. The zone is
authoritative for `azureedge.net`, so the name fails locally and never reaches a resolver outside the
lab.

Do not add a wildcard to `azureedge.net`; it would make the fallback name resolve and remove the
observable.

## Exception for the transfer destination

The exfiltration stage writes to MEGA, which is outside the zone. FS01 carries a name resolution policy
rule for `mega.co.nz`, `mega.nz`, and `mega.io` that sends only those names to the NAT resolver. The
zone on DC01 remains authoritative for the campaign names, and no forwarder is added.

## Forwarders

Remove forwarders on DC01 for the duration of the run. With no forwarder, any name outside the lab
zones fails immediately and the lab cannot reach the internet through DNS. The hosts keep their NAT
adapter for updates when the run is not active.

## Applying the design

```powershell
# on DC01, elevated
Remove-DnsServerForwarder -Force

Add-DnsServerPrimaryZone -Name azureedge.net -ZoneFile azureedge.net.dns
Add-DnsServerResourceRecordA -ZoneName azureedge.net -Name five -IPv4Address 192.168.50.100

Add-DnsServerPrimaryZone -Name checkauj.com -ZoneFile checkauj.com.dns
Add-DnsServerResourceRecordA -ZoneName checkauj.com -Name '@'   -IPv4Address 192.168.50.100
Add-DnsServerResourceRecordA -ZoneName checkauj.com -Name 'www' -IPv4Address 192.168.50.100

Add-DnsServerPrimaryZone -Name millscruelg.com -ZoneFile millscruelg.com.dns
Add-DnsServerResourceRecordA -ZoneName millscruelg.com -Name '@' -IPv4Address 192.168.50.100

Add-DnsServerPrimaryZone -Name perdefue.fr -ZoneFile perdefue.fr.dns
Add-DnsServerResourceRecordA -ZoneName perdefue.fr -Name '@' -IPv4Address 192.168.50.100
```

## Verification

| Query | Expected |
|---|---|
| `nslookup five.azureedge.net` from WS01 | 192.168.50.100 |
| `nslookup checkauj.com` from WS01 | 192.168.50.100 |
| `nslookup volga.azureedge.net` from WS01 | non-existent domain |
| Sysmon E22 for the failed lookup | `QueryStatus: 9003` |

