# Query 26 - Campaign domain lookup

## KQL

```
event.code:22 and dns.question.name:"checkauj.com"
```

## Result

![Campaign domain lookup](screenshot.jpg)

Campaign domain lookup.

Technique: `kill-chain/techniques/process-injection/`. Run: `run-6`, 2026-11-21. Source frame: `run6-26-campaign-domain-lookup.jpg`.
