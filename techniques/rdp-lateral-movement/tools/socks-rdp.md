# RDP through the implant

The connection must originate from the implant, not from the operator workstation. A client running
on the operator host would produce the same target-side logon but a different source-side event, and
the attribution depends on the beacon owning the socket.

## Operator side

```text
sliver > use <session on the backup server>
sliver > socks5 start
```

The client prints the listening port. Connect the RDP client through it:

```bash
proxychains4 -q xfreerdp /v:FS01 /u:<account> /p:<password> /cert-ignore /dynamic-resolution
```

`proxychains4` must point at the SOCKS port; replace the default `socks4 127.0.0.1 9050` entry in
`/etc/proxychains4.conf` with the port printed by the implant.

## Checks

| Side | Check | Expected |
|---|---|---|
| backup server | Sysmon E3 for the implant process | `DestinationPort: 3389`, `Initiated: true` |
| backup server | Security 4624 | `LogonType: 10`, `WorkstationName` not an estate member |
| backup server | Sysmon E1 | `explorer.exe` -> `taskmgr.exe /4` after the GUI is opened |
| operator | process tree | `xfreerdp` owns no direct connection to the target |

## Inside the session

Open the backup console, then start Task Manager from the Start menu. The resulting command line
carries `/4`, which is what the GUI passes for the Performance tab. A command-line launch does not
produce that argument, so the argument is evidence of a human at the console.
