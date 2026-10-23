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

Expected events are listed in [`telemetry/README.md`](telemetry/README.md). The rule
[`detection_rules/sigma/beacon-process-opens-rdp.yml`](detection_rules/sigma/beacon-process-opens-rdp.yml)
matches a non-client process opening 3389. The rule
[`detection_rules/sigma/rdp-type10-logon.yml`](detection_rules/sigma/rdp-type10-logon.yml) matches the
target-side logon.
