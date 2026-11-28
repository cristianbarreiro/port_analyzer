# Roadmap

## Foundation
- [x] Read-only TCP/UDP collection, process enrichment, terminal refresh, initial conservative heuristics.
- [x] Unit coverage for IPv4/IPv6 bind scopes, IPv4-mapped IPv6, malformed addresses, PID 0, process lookup failures, and empty findings.
- [ ] Validate on Windows 10/11 and Windows Server.

## Next
- [ ] Performance testing and configurable filters.
- [ ] Structured JSON schema/versioning and snapshot export.
- [ ] Optional read-only Windows Firewall correlation, clearly separated from actual reachability.
- [ ] Integration tests against supported Windows versions.
- [ ] Signed release artifacts and packaging.
