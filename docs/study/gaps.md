# Gaps

What the lab substitutes for the campaign, and what it cannot show.

| Campaign element | Lab substitute | What is lost |
|---|---|---|
| Privilege escalation from a user macro | an agent that executes scripts from a user-writable directory | no memory-corruption exploit is modelled; the escalation is a configuration weakness |
| Domain administrator credential | backup service running as `C0015\Administrator`, password in LSA secrets | it is a stored secret, not a LSASS hash from an interactive session |
| BazarLoader -> Conti | Sliver beacon and a simulator for the locker | implant and ransomware internals are not reproduced |
| Domain-wide encryption | corpus and shares | no domain-wide blast radius, no boot configuration damage |
| Exfiltration to a cloud remote | rclone to MEGA | no receiver inventory; transfer success is intent plus exit code |
| Domain controller compromise | none | the chain stops at the server; DC techniques are out of scope |

The source report does not document the privilege step, so the lab makes it explicit instead of pretending
it was observed.
