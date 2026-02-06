# 🍯 Honey Claw

**AI-powered honeypot deployment for OpenClaw agents**

Deploy deceptive infrastructure in seconds. Capture attacker TTPs. Let your AI analyze the threats.

```bash
# Deploy a honeypot with one command
openclaw skill honeyclaw deploy --template basic-ssh --name prod-bastion-01
```

## Why Honey Claw?

Traditional honeypots are static and obvious. Honey Claw brings AI-native deception:

- **🐳 Docker-isolated** — Each honeypot runs in a sandboxed container
- **📊 Real-time logging** — All interactions streamed to S3-compatible storage  
- **🎭 Adaptive responses** — AI agents can respond to attackers dynamically
- **⚡ Instant deployment** — Spin up convincing decoys in seconds
- **🔍 TTP extraction** — Automatic MITRE ATT&CK mapping of attacker behavior

## Templates

| Template | Interaction Level | Use Case |
|----------|------------------|----------|
| `basic-ssh` | Low | SSH brute-force detection, credential harvesting |
| `fake-api` | Medium | API abuse detection, token theft attempts |
| `enterprise-sim` | High | Full enterprise simulation, APT detection |

## Quick Start

### 1. Install the Skill

```bash
# Add to your OpenClaw agent
openclaw skill add honeyclaw
```

### 2. Deploy Your First Honeypot

```bash
# Low-interaction SSH honeypot
openclaw skill honeyclaw deploy \
  --template basic-ssh \
  --name suspicious-server-01 \
  --port 2222

# Medium-interaction fake API
openclaw skill honeyclaw deploy \
  --template fake-api \
  --name api-staging \
  --port 8080

# High-interaction enterprise simulation
openclaw skill honeyclaw deploy \
  --template enterprise-sim \
  --name corp-dc-backup \
  --ports 22,80,443,3389,5985
```

### 3. Monitor Attacks

```bash
# Stream live attack logs
openclaw skill honeyclaw logs --follow

# Get attack summary
openclaw skill honeyclaw report --last 24h
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    OpenClaw Agent                        │
│  ┌─────────────────────────────────────────────────┐    │
│  │              Honey Claw Skill                    │    │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────────────┐   │    │
│  │  │ Deploy  │ │ Monitor │ │ Analyze (AI)    │   │    │
│  │  └────┬────┘ └────┬────┘ └────────┬────────┘   │    │
│  └───────┼───────────┼───────────────┼────────────┘    │
└──────────┼───────────┼───────────────┼──────────────────┘
           │           │               │
           ▼           ▼               ▼
    ┌──────────┐ ┌──────────┐   ┌──────────┐
    │  Docker  │ │ S3 Logs  │   │  MITRE   │
    │ Sandbox  │ │ Storage  │   │ ATT&CK   │
    └──────────┘ └──────────┘   └──────────┘
```

## Log Format

All interactions are logged in structured JSON:

```json
{
  "timestamp": "2026-02-05T17:30:00Z",
  "honeypot_id": "prod-bastion-01",
  "template": "basic-ssh",
  "event_type": "auth_attempt",
  "source_ip": "45.33.32.156",
  "source_port": 54321,
  "payload": {
    "username": "admin",
    "password": "admin123",
    "client_version": "SSH-2.0-libssh_0.9.4"
  },
  "mitre_tactics": ["TA0001"],
  "mitre_techniques": ["T1078"]
}
```

## Configuration

```yaml
# honeyclaw.yaml
storage:
  type: s3
  bucket: honeyclaw-logs
  endpoint: https://s3.amazonaws.com  # or MinIO, R2, etc.
  
defaults:
  network: honeyclaw-net
  log_level: debug
  auto_analyze: true
  
alerts:
  slack_webhook: ${SLACK_WEBHOOK_URL}
  threshold: 10  # alerts per hour
```

## Security Considerations

⚠️ **Honeypots attract attackers by design.** 

- Run on isolated networks only
- Never deploy on production infrastructure
- Monitor resource usage (cryptominer detection)
- Use network segmentation
- Regularly rotate honeypot instances

## Roadmap

- [x] Basic SSH honeypot template
- [x] Fake API honeypot template
- [x] S3-compatible log storage
- [ ] AI-powered dynamic responses
- [ ] Automatic IOC extraction
- [ ] Integration with threat intel feeds
- [ ] Distributed honeypot mesh
- [ ] Real-time Slack/Discord alerts

## License

MIT License - See [LICENSE](LICENSE)

---

*Part of the OpenClaw ecosystem. Built for agents, by agents.* 🦞
