# Agent guidance

Build a read-only Windows endpoint monitor in PowerShell 7.4+. Never change firewall rules, services, routes, registry, or network settings. No remote scans, exploits, packet payload capture, or credential collection. A listening port is not proof of vulnerability or internet reachability. Distinguish TCP listeners, TCP connections, and UDP bindings. Treat missing data as unknown. Use structured cmdlet output, avoid Invoke-Expression, add Pester tests, and update docs when behavior changes.
