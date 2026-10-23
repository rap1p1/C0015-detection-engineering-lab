# Conti-style impact through admin shares

The final step is a batch file executed on the backup server. For each reachable host it starts a
locker binary against the administrative share of the target:

```
C:\<random>_locker.exe -m -net -size 10 -nomutex -p \\<TARGET>\C$
```

`-p` selects the path, `-net` selects network mode, `-size 10` sets the chunk size, `-nomutex` drops
the single-instance guard, and `-m` selects the encryption mode. The binary renames encrypted files
and writes `readme.txt` into every affected directory. Afterwards the operator lists `\\<TARGET>\C$`
to confirm the result.

## How the lab reproduces it

The lab keeps the deployment shape and replaces the encryption routine. `payload/locker.bat.tpl`
renders one line per target host with the campaign flag set; `payload/locker_sim.c` accepts the same
arguments, renames files in the allowlisted corpus, and writes `payload/readme.txt` into each
directory it touches. No content is encrypted, no key material is generated, and every action is
reversible.

The corpus is a dedicated directory tree, and the batch file is executed from the backup server, so
the origin of the impact matches the campaign. The lab does not write to `C$` of other hosts; the
share path is rendered into the command line for fidelity and the simulated action is confined to the
local corpus.

`tools/run-impact.ps1` renders the batch file, executes it, verifies the note spread, and restores the
corpus from a hash-checked copy.

## Artifacts

| File | Purpose |
|---|---|
| `payload/locker.bat.tpl` | Per-target launcher with the campaign argument set |
| `payload/locker_sim.c` | Argument-compatible, reversible transformation |
| `payload/readme.txt` | Ransom note text |

## Telemetry and detection

Expected events are listed in [`telemetry/README.md`](telemetry/README.md). The rule
[`detection_rules/sigma/locker-binary-argument-set.yml`](detection_rules/sigma/locker-binary-argument-set.yml)
matches the argument combination, and
[`detection_rules/sigma/ransom-note-spread.yml`](detection_rules/sigma/ransom-note-spread.yml) matches
the same note file appearing in several directories within a short window.
