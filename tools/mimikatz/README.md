# Mimikatz

| | |
|---|---|
| Version | 2.2.0 (binary in this folder) |
| Obtained from | https://github.com/gentilkiwi/mimikatz/releases |
| Used in | credential access, on WS01 as SYSTEM |

## Command used

```
mimikatz.exe "privilege::debug" "lsadump::secrets" exit
```

`lsadump::secrets` reads the LSA secrets, where Windows stores the password of accounts used by services
and scheduled tasks. The lab maintenance task runs as `C0015\Administrator`, so the recovered secret is
the domain administrator password.

## Telemetry

- Sysmon 1: `mimikatz.exe` with those arguments.
- Security 4688 if command line auditing is on.
- No LSASS process access: this is not `sekurlsa`, so a rule built only on E10 will not see it.

## Detection

Planned R23: mimikatz command line or `lsadump::secrets` on a host. R05 stays for `sekurlsa`.
