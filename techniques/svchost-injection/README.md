# svchost injection (CDPUserSvc)

On the backup server, `143.dll` is loaded by `rundll32.exe` under `WmiPrvSE.exe`. The beacon then
moves into `svchost.exe -k UnistackSvcGroup -s CDPUserSvc`, the per-user service host instance. That
instance runs as the logged-on user, not as SYSTEM, which is why the injection succeeds without an
additional privilege step.

The host choice also explains the network behaviour: the callback after the injection originates from
`svchost.exe`, and the RDP connection opened later is owned by the same process.

## How the lab reproduces it

After the WMI-created `rundll32.exe` registers its session, the operator selects it and migrates into
the service host by PID:

```
# find the instance that hosts CDPUserSvc
ps -e | grep "UnistackSvcGroup"
migrate --pid <pid>
```

The PID lookup is deliberate. Several `svchost.exe` instances exist and only one carries
`-k UnistackSvcGroup -s CDPUserSvc`; migrating by name would land in an arbitrary instance and break
the fidelity of the edge.

`tools/migrate-to-cdpusersvc.txt` records the sequence and the checks. The original `rundll32.exe`
session is kept to preserve the `WmiPrvSE -> rundll32` evidence for the pivot stage.

## Artifacts

| File | Purpose |
|---|---|
| `tools/migrate-to-cdpusersvc.txt` | PID discovery, migration, verification |

## Telemetry and detection

Expected events are listed in [`telemetry/README.md`](telemetry/README.md). The rule
[`detection_rules/sigma/rundll32-injects-system-process.yml`](detection_rules/sigma/rundll32-injects-system-process.yml)
covers the thread creation into `svchost.exe`. The network side is covered by
`detection_rules/sigma/service-host-egress.yml`, which matches an unexpected service host making an
outbound connection.
