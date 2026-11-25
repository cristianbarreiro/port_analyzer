# Threat model

Assets: host availability/configuration, integrity of observations, and accurate user understanding. Risks include false positives from port numbers, false assurance from missing findings, PID/process races, and missing privileges. Mitigations: findings include evidence and low confidence; missing data is surfaced; process attribution is best effort; no elevation is required by default. Remote scanning, exploitation, payload capture, credentials, and automatic remediation are out of scope.
