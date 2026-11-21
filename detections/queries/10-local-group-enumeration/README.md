# Query 10 - Local group enumeration

## KQL

```
event.code:1 and process.name:("net.exe" or "net1.exe") and process.command_line:*localgroup*
```

## Result

![Local group enumeration](screenshot.jpg)

Local group enumeration.

Technique: `kill-chain/techniques/discovery/`. Run: `run-6`, 2026-11-21. Source frame: `run6-10-local-group-enumeration.jpg`.
