# 🍯 Honey Claw

**AI-powered honeypot deployment for OpenClaw agents**

Deploy deceptive infrastructure in seconds. Capture attacker TTPs. Let your AI analyze the threats.

```bash
# Deploy a honeypot with one command
openclaw skill honeyclaw deploy --template basic-ssh --name prod-bastion-01
```

## 🚀 Live Deployment

**Honey Claw SSH Honeypot is LIVE!**

| Property | Value |
|----------|-------|
| **IP Address** | `149.248.202.23` |
| **Port** | `8022` |
| **App** | `honeyclaw-ssh` on Fly.io |
| **Region** | sjc (San Jose) |

```bash
# Test the honeypot (it will capture your attempt!)
ssh -p 8022 admin@149.248.202.23
```

> 💡 **Note:** Uses port 8022 because Fly.io reserves port 22 for its internal SSH proxy.

---

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

## Development

### Prerequisites

- Python 3.11+
- Docker 24+ (for container templates)
- Fly.io CLI (for deployment)

### Local Development

```bash
# Clone the repository
git clone https://github.com/sarahtwilliams412-bit/honeyclaw
cd honeyclaw

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install asyncssh aiohttp

# Run the SSH honeypot locally
python templates/basic-ssh/honeypot.py
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8022` | Listening port |
| `LOG_PATH` | `/var/log/honeypot/ssh.json` | Log file path |
| `HOST_KEY_PATH` | `/data/ssh_host_key` | Persistent SSH host key |
| `HONEYPOT_ID` | `basic-ssh` | Instance identifier |

### Testing

```bash
# Test SSH honeypot connection (will log your attempt!)
ssh -p 8022 test@localhost

# View logs
tail -f /var/log/honeypot/ssh.json
```

---

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
