# Detailed architecture overview

[Reading guide](../README.md) · [Configuration and identities](architecture.md)


```mermaid
flowchart TD

subgraph campaign["Campaign simulation · S1–S14"]
    direction TD

    operator(("Lab operator"))
    c2["C2-SIM · Operator tasks and callbacks"]

    subgraph ws01["WS01 · Initial foothold"]
        direction TD
        entry["Word macro → HTA bootstrap"]
        proxy["Bootstrap DLL · regsvr32"]
        beacon1["Session 1 · PowerShell beacon"]
        local["Discovery and LSASS surrogate"]

        entry --> proxy --> beacon1 --> local
    end

    subgraph fs01["FS01 · Lateral movement"]
        direction TD
        pivot["SMB staging → WMI execution"]
        beacon2["Session 2 · PowerShell beacon"]

        pivot --> beacon2
    end

    subgraph later["Later operator sessions"]
        direction TD
        collection["File collection"]
        transfer["rclone → WebDAV lab sink"]
        remote["RDP and portable remote-access tools"]
        impact["Bounded impact simulation"]

        collection --> transfer
        remote --> impact
    end

    dc01["DC01 · AD DS and DNS"]

    operator -->|"opens document"| entry
    operator -->|"controls sessions"| c2
    c2 <-->|"tasks and callbacks"| beacon1
    c2 <-->|"tasks and callbacks"| beacon2

    local -->|"operator-driven pivot"| pivot
    beacon2 -->|"operator collection task"| collection
    operator -->|"interactive access"| remote

    dc01 -.->|"domain services"| ws01
    dc01 -.->|"domain services"| fs01
end

subgraph detection["Telemetry and detection"]
    direction TD

    sensors["Sysmon and Windows event logs"]
    agents["Elastic Agent · WS01 and FS01"]
    fleet["Fleet · Agent policies"]
    elastic[("Elasticsearch · Raw events")]
    queries["Version-controlled detection queries"]
    exports["NDJSON rule exports"]
    rules["Elastic Security · Rules and alerts"]

    sensors -->|"collect"| agents
    fleet -.->|"manages"| agents
    agents -->|"ingest"| elastic
    queries -->|"generate"| exports
    exports -->|"import"| rules
    elastic -->|"evaluate"| rules
end

subgraph evidence["Evidence and validation"]
    direction TD

    artifacts["Artifacts, manifests and sink receipts"]
    ledger[("Run evidence ledger")]
    report["Acceptance findings and reference report"]

    artifacts -->|"paths and hashes"| ledger
    ledger -->|"supports conclusions"| report
end

ws01 -.->|"host telemetry"| sensors
fs01 -.->|"host telemetry"| sensors

transfer -->|"per-file receipts"| artifacts
impact -->|"verify and rollback results"| artifacts
elastic -->|"event IDs, fields and UTC timestamps"| ledger
rules -->|"alert references"| ledger

classDef execution fill:#dbeafe,stroke:#2563eb,stroke-width:1.5px,color:#172554
classDef operations fill:#fef3c7,stroke:#d97706,stroke-width:1.5px,color:#78350f
classDef telemetry fill:#dcfce7,stroke:#16a34a,stroke-width:1.5px,color:#14532d
classDef evidenceTone fill:#ffe4e6,stroke:#e11d48,stroke-width:1.5px,color:#881337
classDef infrastructure fill:#e0e7ff,stroke:#4f46e5,stroke-width:1.5px,color:#312e81

class entry,proxy,beacon1,beacon2 execution
class local,pivot,collection,transfer,remote,impact operations
class sensors,agents,fleet,elastic,queries,exports,rules telemetry
class artifacts,ledger,report evidenceTone
class operator,c2,dc01 infrastructure

style campaign fill:none,stroke:none,color:#c9d1d9
style ws01 fill:#eff6ff,stroke:#93c5fd,color:#172554
style fs01 fill:#eff6ff,stroke:#93c5fd,color:#172554
style later fill:#fffbeb,stroke:#fcd34d,color:#78350f
style detection fill:none,stroke:none,color:#c9d1d9
style evidence fill:none,stroke:none,color:#c9d1d9
```

Fleet manages endpoint policies. Elastic Agents collect Sysmon and Windows Security events and send
them to Elasticsearch, where Elastic Security evaluates the detection rules. The evidence ledger connects
source events and alerts with the artifacts produced during each run.

| System | Role | Lab address |
|---|---|---|
| WS01 | Windows 10 workstation; initial foothold and session 1 | `192.168.50.20` |
| FS01 | Windows 10 Pro file server; Finance/IT data, WMI pivot, and session 2 | `192.168.50.30` |
| DC01 | AD DS and DNS for `c0015.lab` | `192.168.50.10` |
| Windows host | Operator, HTTP staging, C2-SIM, and WebDAV sink | `192.168.50.1` |
| Kali | Auxiliary tooling and Tailscale routing | `192.168.50.100` |
| ELASTIC01 | Elasticsearch, Kibana, and Fleet Server | Tailscale `100.77.46.126` |

The domain network uses VMware VMnet2 (`192.168.50.0/24`, host-only). WS01 and FS01 also have
NAT adapters for installation and updates. The Windows host serves HTTP staging on `:8000`, C2-SIM
on `:8080`, and the WebDAV sink on `:9001`. Endpoint telemetry uses the Elastic namespace `c0015`.
