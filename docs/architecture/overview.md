# Architecture

The MVP has four stages: collection using local Windows networking cmdlets; best-effort process enrichment; pure heuristic analysis over normalized objects; and a refreshed terminal dashboard. Collection is read-only. Firewall policy and remote reachability are separate concerns and are not inferred from socket state.
