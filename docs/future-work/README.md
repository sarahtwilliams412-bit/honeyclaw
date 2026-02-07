# Future Work

Actionable tasks remaining from the 2026-02-07 security audit review. Each file describes a self-contained project suitable for a single contributor.

For the broader long-term roadmap, see [docs/IMPROVEMENT-PLAN.md](../IMPROVEMENT-PLAN.md).
For the full audit report, see [SECURITY-AUDIT-2026-02-07.md](../../SECURITY-AUDIT-2026-02-07.md).

## Task Index

| File | Priority | Effort | Summary |
|------|----------|--------|---------|
| [01-fix-ssh-handshake.md](01-fix-ssh-handshake.md) | Critical | Medium | SSH KEX failure — honeypot can't capture credentials |
| [02-log-rotation.md](02-log-rotation.md) | High | Small | Logs grow unbounded, will exhaust disk |
| [03-openssh-algorithm-ordering.md](03-openssh-algorithm-ordering.md) | Medium | Medium | asyncssh algorithm order differs from real OpenSSH |
| [04-anti-fingerprinting.md](04-anti-fingerprinting.md) | Medium | Large | Shodan/timing/response fingerprinting resistance |
| [05-rerun-input-validation.md](05-rerun-input-validation.md) | High | Small | 50 of 55 tests were inconclusive due to KEX failure |
| [06-webhook-alerting-setup.md](06-webhook-alerting-setup.md) | Medium | Small | Configure ALERT_WEBHOOK_URL for production |
| [07-threat-intel-enrichment.md](07-threat-intel-enrichment.md) | Medium | Medium | Integrate AbuseIPDB/GreyNoise for IP reputation |

## How to Pick a Task

- **New contributors**: Start with `02-log-rotation.md` or `06-webhook-alerting-setup.md` (small, well-scoped)
- **SSH/asyncssh experience**: `01-fix-ssh-handshake.md` is the most impactful task
- **Security researchers**: `03-openssh-algorithm-ordering.md` and `04-anti-fingerprinting.md` require protocol analysis
- **After SSH is fixed**: `05-rerun-input-validation.md` must be done to validate the security posture

## Completed Tasks (from this audit)

- ~~Health check endpoint~~ -- Added HTTP /health on :9090
- ~~Volume mount for log persistence~~ -- Added [mounts] to fly.toml
- ~~Host key persistence~~ -- ed25519 key saved to volume
- ~~Correlation module loading~~ -- Fixed __init__.py and Dockerfile
- ~~GeoIP module loading~~ -- Fixed import path
- ~~Misleading test results~~ -- Corrected 55/55 to 5/55 confirmed
