# Query 41 - Everything the rules can see

## KQL

```
event.code:(1 or 3 or 7 or 8 or 11 or 22) and host.name:("ws01" or "fs01")
```

## Result

![Everything the rules can see](screenshot.jpg)

Everything the rules can see.

Technique: `kill-chain/techniques/kill-chain/`. Run: `run-6`, 2026-11-21. Source frame: `run6-41-everything-the-rules-can-see.jpg`.
