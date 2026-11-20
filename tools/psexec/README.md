# PsExec

| | |
|---|---|
| Source | Sysinternals |
| Used in | lateral movement alternative to WMI |
| Telemetry | Security 7045, Sysmon 1 for the service binary |

```
PsExec64.exe \\FS01 -u C0015\Administrator -p <password> -s cmd.exe
```

The service runs as SYSTEM regardless of the account used to create it. Leaves a service and a binary in
`C:\Windows`; both are usually deleted after the run.
