# vssadmin

Built into Windows. Used to destroy volume shadow copies before the ransomware runs, which removes the
quickest recovery path.

```
vssadmin delete shadows /all /quiet
```

Telemetry: Sysmon 1 (`vssadmin.exe` with `delete shadows`), and 4688 when command line auditing is on.
