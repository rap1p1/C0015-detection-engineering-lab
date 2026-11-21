# Query 15 - Mimikatz process

## KQL

```
event.code:1 and process.name:"mimi.exe"
```

## Result

![Mimikatz process](screenshot.jpg)

Mimikatz process.

Technique: `kill-chain/techniques/credential-access-lsa-secrets/`. Run: `run-6`, 2026-11-21. Source frame: `run6-15-mimikatz-process.jpg`.
