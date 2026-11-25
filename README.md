# Port Analyzer

Real-time, read-only Windows network endpoint monitor built with PowerShell 7.

> Status: foundation in progress. The project distinguishes local socket state from network exposure; a listening port is not, by itself, proof of remote reachability or vulnerability.

## Goals

- Show TCP listeners, established TCP connections, and UDP endpoints in a live terminal dashboard.
- Associate endpoints with owning processes when permissions and platform data allow.
- Explain bind scope and local exposure without overstating internet reachability.
- Provide conservative, evidence-based security findings with actionable remediation.
- Export normalized observations as JSON.

## Safety principles

- Read-only by default: never changes firewall rules, services, routes, registry, or network configuration.
- No implicit remote scanning, packet payload capture, credential collection, or exploit attempts.
- A port number alone never establishes that a service is vulnerable.
- Missing permissions or data are reported as unknown, not silently treated as safe.

## Requirements

- Windows 10/11 or Windows Server with supported networking cmdlets.
- PowerShell 7.4 or later (Windows PowerShell 5.1 compatibility is not a goal for the initial MVP).

## Quick start

The live dashboard is being implemented. See [ROADMAP.md](ROADMAP.md) for the initial milestones.

## License

MIT (see [LICENSE](LICENSE)).
