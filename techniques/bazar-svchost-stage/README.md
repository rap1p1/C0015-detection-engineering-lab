# svchost stage hosting

The loader hands off to a `svchost.exe` that hosts the stage. Two DLLs are then loaded through
`rundll32.exe` with `svchost.exe` as the parent: `D574.dll`, which only produces DNS queries for
`volga.azureedge.net` and never establishes a connection, and `D8B3.dll`, the beacon that is used for
the rest of the intrusion.

The `svchost.exe -> rundll32.exe` edge is what makes the later SYSTEM context possible. Every child
process created from that point runs with the integrity level of the host.

## How the lab reproduces it

A service DLL hosts the stage inside `svchost.exe -k c0015grp` and spawns
`rundll32.exe C:\Users\Public\C0015\D8B3.dll`. svchost runs as SYSTEM, so the child inherits SYSTEM
without a separate privilege operation, and the process tree contains the campaign edge.

`payload/c0015_svc_stub.c` exports `ServiceMain`, reads `[stage] spawn_cmd` from `config.ini`,
creates the child, and stays alive until the child exits so the parent image remains resolvable in
telemetry. `tools/install_stage_service.ps1` creates the service, sets `Parameters\ServiceDll`, adds
the service to the `Svchost` group, and verifies the resulting tree.

The service installation adds events that the original intrusion does not contain: Security 7045 and
the service registry keys. They are a lab mechanism, not campaign behaviour, and they are the price
of reproducing the host-process edge without a real loader.

The dead beacon is reproduced by generating a second module pointed at a name that does not resolve
in the lab DNS zone. The implant retries, the queries fail, and no connection is established.

## Artifacts

| File | Purpose |
|---|---|
| `payload/c0015_svc_stub.c` | `ServiceDll` that spawns the configured host process as SYSTEM |
| `tools/install_stage_service.ps1` | Creates, configures, starts, and removes the service |

## Telemetry and detection

Expected events are listed in [`telemetry/README.md`](telemetry/README.md). The rule
[`detection_rules/sigma/svchost-spawns-rundll32.yml`](detection_rules/sigma/svchost-spawns-rundll32.yml)
matches a `rundll32.exe` whose parent is `svchost.exe`, and the accompanying DNS rule matches repeated
lookups that return a non-existent name.
