# Open Knowledge Format — source register

| Topic | Primary source | Use |
|---|---|---|
| TCP sockets | Microsoft Learn: Get-NetTCPConnection | Local TCP state, addresses, ports, PID |
| UDP sockets | Microsoft Learn: Get-NetUDPEndpoint | Local UDP endpoints and PID |
| Process metadata | Microsoft Learn: Get-Process | Best-effort process enrichment |
| Tests | Pester documentation | Automated test framework |
| Static analysis | PSScriptAnalyzer documentation | PowerShell quality checks |

Interpretation: TCP Listen is local socket state, not proof of remote reachability. UDP has no TCP LISTEN state. Wildcard bind means binding across local interfaces, not guaranteed internet exposure. Port heuristics are review hints, not CVE verification.

Verification log: 2026-11-25 — initial register; validate cmdlet properties against supported Windows versions in CI.
