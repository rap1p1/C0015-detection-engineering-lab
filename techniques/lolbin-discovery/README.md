# Discovery through LOLBins

Discovery runs from the injected `winlogon.exe`. Each command is a separate `cmd.exe` with a single
`/C` argument, so the process list contains a sequence of short-lived shells whose parent is a
SYSTEM process:

```
cmd.exe /C tasklist /s <host>
cmd.exe /C net group "domain admins" /dom
cmd.exe /C net localgroup "administrator"
cmd.exe /C nltest /domain_trusts /all_trusts
cmd.exe /C net view /all /domain
cmd.exe /C net view \\<host> /all
cmd.exe /C ping <host>
cmd.exe /C time
```

The set maps to account discovery, domain trust discovery, remote system discovery, process
discovery, and system time discovery. `AdFind` was written to disk during the same window and never
executed.

## How the lab reproduces it

`tools/discovery-runbook.ps1` issues the commands one at a time through the winlogon session, with a
short interval between them. Each call is a single `cmd.exe /C` invocation, so the parent image stays
`winlogon.exe` and the process name is `cmd.exe` rather than a long-lived shell.

The runbook keeps the parameter spelling of the campaign, including the per-host `net view` form. The
lab does not add `whoami`, `systeminfo`, or other commands that the campaign does not contain, so the
telemetry stays comparable.

`tools/collect-output.ps1` gathers the results from the console output and writes a single text file
per run, which is the input for the target-selection step.

## Artifacts

| File | Purpose |
|---|---|
| `tools/discovery-runbook.ps1` | Ordered command set, one process per command |
| `tools/collect-output.ps1` | Collects command output for the run record |

## Telemetry and detection

The rule for this behaviour lives in [`detections/eql/`](../../detections/eql/) and is listed in the index at [`detections/README.md`](../../detections/README.md). The field assumptions the rule depends on are recorded there.


