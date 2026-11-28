# Port Analyzer

Real-time, read-only Windows network endpoint monitor built with PowerShell 7.4+.

## Quick start

Open PowerShell 7 in this directory and run:

```powershell
.\Start-PortAnalyzer.ps1
```

Useful options:

```powershell
.\Start-PortAnalyzer.ps1 -RefreshSeconds 1
.\Start-PortAnalyzer.ps1 -Once
.\Start-PortAnalyzer.ps1 -Once -Json
```

The dashboard displays TCP listeners, TCP connections, UDP endpoints, owning process names where available, bind scope, and conservative review hints.

## Interpretation and safety

- Read-only: it does not modify firewall rules, services, routes, registry, or network settings.
- TCP LISTEN is local socket state, not proof of remote or internet reachability.
- UDP endpoints are bindings, not TCP listeners.
- Port-number heuristics are review hints, not vulnerability detection or CVE confirmation.
- Wildcard, loopback, specific, and unparseable addresses are classified separately; unparseable values remain **Unknown**.
- PID 0 is identified as the System Idle Process without attempting a process lookup. Other process attribution is best effort and may be **Unknown** if a process exits or access is denied.
- Firewall, NAT, VPN, routing, and upstream controls are not yet correlated.
- An empty result or missing data is not proof that a host is secure.

See [AGENTS.md](AGENTS.md), [SECURITY.md](SECURITY.md), [architecture](docs/architecture/overview.md), and [roadmap](ROADMAP.md).

## Requirements

Windows with NetTCPIP cmdlets and PowerShell 7.4 or later. Automated tests run on Windows in GitHub Actions.

## License

MIT.
