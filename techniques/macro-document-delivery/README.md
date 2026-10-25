# Macro document delivery

The intrusion starts with a password-protected archive delivered by phishing. The archive contains
a Word document whose file name ends in `.doc` but whose content is Word 2003 XML with an embedded
VBA project. Word prompts for macro enablement; the user accepts, and the macro runs.

The macro carries the next stage as base64 chunks. On open it decodes them and writes two files into
the user profile: `compareforfor.hta` and a configuration file. It then starts the HTA through
`cmd.exe /c mshta`, which yields the `WINWORD.EXE -> cmd.exe -> mshta.exe` edge.

## How the lab reproduces it

`payload/gen_macro_embedded.ps1` builds the standard module `c0015Payload` from
`payload/macro_payload.vba` and the base64 blobs, writing a native file writer so the macro does not
depend on late binding for the payload bytes. `payload/install_macro_docm.ps1` injects that module
into a document's own VB project and saves it as a macro-enabled document.

The macro is a thin launcher: it reads `[bootstrap] hta_path` and `mshta_path` from
`config.ini`, writes the HTA if it is absent, then runs the HTA through `cmd.exe`. Keeping the
launcher separate from the payload means the same document can drive different stage-2 artifacts
without editing VBA.

## Artifacts

| File | Purpose |
|---|---|
| `payload/macro_payload.vba` | Module source: `AutoOpen` launcher and file writers |
| `payload/gen_macro_embedded.ps1` | Builds the self-contained module with embedded blobs |
| `payload/install_macro_docm.ps1` | Injects the module and saves the delivery document |

## Telemetry and detection

The rule for this behaviour lives in [`detections/eql/`](../../detections/eql/) and is listed in the index at [`detections/README.md`](../../detections/README.md). The field assumptions the rule depends on are recorded there.


