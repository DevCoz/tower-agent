# Tower Agent v3.0.0

- Protocol 4 only; unified Snell, Shadowsocks, Trojan and AnyTLS service lifecycle.
- Verified runtime downloads, isolated systemd credentials, candidate validation, local health checks and rollback.
- Self-signed and certbot ACME certificates, renewal observations and private-key retention on host.
- Durable task receipts, restart recovery, configuration digest verification and revision/lease fencing.
- Exact runtime versions and explicit historical rollback; health evidence retains its original check time on replay.

Requires a fresh protocol 4 Tower Panel, Linux amd64/arm64 and systemd 247+. ACME additionally requires certbot and reachable HTTP-01. No old database migration or service adoption. Local tests and cross-compilation do not replace real Linux/ACME acceptance tests; this build has not been published.
