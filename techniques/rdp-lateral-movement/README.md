# RDP through the beacon

The operator does not connect to the backup server directly. RDP is tunnelled through the implant,
so the TCP connection to port 3389 is owned by the beacon's host process rather than by a client on
the operator workstation. On the target, the session appears as an interactive logon with a
workstation name that does not belong to the estate.

Inside the session the operator uses graphical tools: the backup console, Task Manager started from
the Start menu, and later ProcessHacker. `taskmgr.exe` carries the `/4` argument, which is what the
GUI passes when the Performance tab is opened; a command-line launch does not produce it.

## How the lab reproduces it

The implant starts a SOCKS proxy, and the operator connects an RDP client through it:

```
sliver > socks5 start
# operator host
proxychains4 xfreerdp /v:<backup server> /u:<account> /p:<password> /cert-ignore
```

The observable result is the same as the campaign: the beacon process initiates the connection to
3389, and the target records an interactive logon. The lab keeps the session short but performs the
same actions inside it: open the backup console, start Task Manager from the GUI, and confirm the
process list.

`tools/socks-rdp.md` records the client invocation and the events to check on both sides.

## Artifacts

| File | Purpose |
|---|---|
| `tools/socks-rdp.md` | Proxy setup, client invocation, verification |

## Telemetry and detection

The rule for this behaviour lives in [`detections/eql/`](../../detections/eql/) and is listed in the index at [`detections/README.md`](../../detections/README.md). The field assumptions the rule depends on are recorded there.



## Status

Attempted from the session hosted by `winlogon.exe` on the workstation. The proxy started on 1081,
the relay in `tools/rdp-via-socks.sh` listened on 13389 and forwarded to `FS01:3389`, and the client
completed the TLS handshake with the target, but the interactive session did not finish negotiating
through the in-band proxy and no type 10 logon was recorded.

The next attempt should use a raw TCP pivot rather than the in-band SOCKS proxy, and should keep the
same requirement: the process that owns the 3389 socket must be the implant, and the logon on the
target must be type 10 with a workstation name that is not an estate member.

