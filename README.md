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

## 🌐 Geo-Distributed Mesh

Deploy honeypots across multiple regions for **cross-region attacker correlation**. Detect sophisticated attackers probing your infrastructure from multiple locations.

### Quick Deploy (3 Regions)

```bash
# Deploy to US-West, US-East, and Europe
./scripts/deploy-mesh.sh

# Or specify custom regions
./scripts/deploy-mesh.sh sjc iad ams sin  # US-West, US-East, Amsterdam, Singapore
```

### Mesh Architecture

```
                    ┌─────────────────────────────────┐
                    │     Mesh Coordinator            │
                    │  (Central IOC Database)         │
                    │  - Attacker correlation         │
                    │  - Cross-region alerts          │
                    │  - Threat scoring               │
                    └───────────────┬─────────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          │                         │                         │
          ▼                         ▼                         ▼
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│   US-West Node  │      │   US-East Node  │      │   EU-Central    │
│   (sjc)         │      │   (iad)         │      │   (ams)         │
│                 │      │                 │      │                 │
│ - SSH Honeypot  │      │ - SSH Honeypot  │      │ - SSH Honeypot  │
│ - Event logging │      │ - Event logging │      │ - Event logging │
└─────────────────┘      └─────────────────┘      └─────────────────┘
```

### Mesh Configuration

Add mesh configuration to your `honeyclaw.yaml`:

```yaml
mesh:
  enabled: true
  coordinator_url: https://honeyclaw-coordinator.fly.dev
  node_id: auto  # Auto-generate from hostname + region
  region: us-west
  heartbeat_interval: 30
  batch_size: 50

# Standard honeypot config continues below...
storage:
  type: s3
  bucket: honeyclaw-logs
```

### Environment Variables (Mesh)

| Variable | Default | Description |
|----------|---------|-------------|
| `MESH_ENABLED` | `false` | Enable mesh mode |
| `MESH_COORDINATOR_URL` | - | Coordinator API URL |
| `MESH_TOKEN` | - | Authentication token |
| `MESH_NODE_ID` | auto | Node identifier |
| `MESH_REGION` | - | Deployment region |
| `MESH_HEARTBEAT_SEC` | `30` | Heartbeat interval |

### Cross-Region Correlation

When an attacker is detected in **multiple regions**, threat score increases:

| Regions | Base Score | Multi-Region Bonus | Total |
|---------|------------|-------------------|-------|
| 1 | 30 | +0 | 30 |
| 2 | 30 | +25 | 55 |
| 3+ | 30 | +40 | 70+ |

### Monitor Your Mesh

```bash
# Check mesh status
curl https://honeyclaw-coordinator.fly.dev/health

# View active nodes
curl -H "Authorization: Bearer $MESH_TOKEN" \
  https://honeyclaw-coordinator.fly.dev/nodes

# Get mesh statistics
curl -H "Authorization: Bearer $MESH_TOKEN" \
  https://honeyclaw-coordinator.fly.dev/stats

# List multi-region attackers
curl -H "Authorization: Bearer $MESH_TOKEN" \
  "https://honeyclaw-coordinator.fly.dev/attackers?multi_region=true"

# Get IOCs
curl -H "Authorization: Bearer $MESH_TOKEN" \
  "https://honeyclaw-coordinator.fly.dev/iocs?min_confidence=0.7"
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check (no auth) |
| `/stats` | GET | Mesh statistics |
| `/nodes` | GET | List active nodes |
| `/nodes/register` | POST | Register new node |
| `/nodes/heartbeat` | POST | Node heartbeat |
| `/events` | POST | Record single event |
| `/events/batch` | POST | Record batch of events |
| `/attackers` | GET | List attacker profiles |
| `/iocs` | GET/POST | IOC database |
| `/alerts` | GET | Correlation alerts |

---

## 🐤 Canary Tokens

Built-in canary token generation for defense-in-depth. Create tokens that alert when accessed, used, or stolen.

### Supported Canary Types

| Type | Description | Use Case |
|------|-------------|----------|
| `aws-key` | Fake AWS credentials (AKIA...) | Detect credential theft |
| `tracking-url` | Unique URLs that alert on visit | Hidden links in docs/configs |
| `dns` | Hostnames that alert on lookup | Embedded in configs/scripts |
| `credential` | Fake username/password pairs | SSH/database honeycreds |
| `webhook` | Generic tokens for custom detection | Flexible embedding |

### Quick Start

```bash
# Create an AWS key canary
honeyclaw canary create --type aws-key \
  --webhook https://hooks.slack.com/services/xxx \
  --memo "Hidden in .aws/credentials on fileserver"

# Create a tracking URL
honeyclaw canary create --type tracking-url \
  --webhook https://hooks.example.com/alert \
  --memo "Embedded in internal wiki"

# Create fake credentials
honeyclaw canary create --type credential \
  --webhook https://hooks.example.com/alert \
  --username backup_admin \
  --memo "Fake DB creds in .env"

# List all canaries
honeyclaw canary list

# View canary details
honeyclaw canary show cnry_abc123

# View dashboard
honeyclaw canary dashboard

# Start tracking server (for URL canaries)
honeyclaw canary server --port 8080
```

### Output Example

```
✅ Canary created successfully!

Canary ID: cnry_a1b2c3d4e5f6
Type: aws-key
Created: 2026-02-06T09:15:00Z
Memo: Hidden in .aws/credentials on fileserver
Webhook: https://hooks.slack.com/services/xxx

AWS Credentials (FAKE - for detection only):
  Access Key ID:     AKIAIOSFODNN7EXAMPLE
  Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY
```

### Embed Canaries Automatically

Generate honeypot files with canaries pre-embedded:

```bash
# Generate fake config files with canaries
honeyclaw canary generate-files \
  --output /opt/honeypot/fake-home \
  --webhook https://hooks.example.com/alert
```

This creates files like:
- `.aws/credentials` (with fake AWS keys)
- `.env` (with fake database credentials)
- `config/database.yml` (with fake connection strings)
- `passwords.txt` (decoy password file)
- `backup_keys.pem` (fake SSH key)

### Dashboard

View all canary activity at a glance:

```
============================================================
           🍯 HONEY CLAW CANARY DASHBOARD
============================================================

📊 Overview (as of 2026-02-06T09:20:00)
   Total Canaries:     12
   Triggered:          3 🚨
   Total Events:       47
   Events (24h):       8

📁 Canaries by Type:
   aws-key: 5
   tracking-url: 4
   credential: 3

🔍 Top Source IPs:
   45.33.32.156: 12 events
   185.220.101.42: 8 events
   192.168.1.100: 5 events

📋 Recent Events:
   [2026-02-06T09:18:42] aws-key from 45.33.32.156
   [2026-02-06T08:55:13] tracking-url from 185.220.101.42
   [2026-02-06T07:30:01] credential from 192.168.1.100
============================================================
```

### Configuration

Environment variables for canary system:

| Variable | Default | Description |
|----------|---------|-------------|
| `CANARY_STORAGE` | `/data/canaries.json` | Canary database path |
| `CANARY_EVENTS_STORAGE` | `/data/canary_events.json` | Events log path |
| `CANARY_WEBHOOK_URL` | - | Default webhook for alerts |
| `CANARY_TRACKING_DOMAIN` | `http://localhost:8080/canary` | Base URL for tracking |
| `CANARY_DNS_DOMAIN` | - | Base domain for DNS canaries |

### Integration with Honeypots

Canaries are automatically embedded when you deploy honeypots:

```bash
# Deploy honeypot with embedded canaries
openclaw skill honeyclaw deploy \
  --template enterprise-sim \
  --name corp-backup \
  --embed-canaries \
  --canary-webhook https://hooks.example.com/alert
```

### Webhook Payload

When a canary triggers, your webhook receives:

```json
{
  "event": "canary_triggered",
  "timestamp": "2026-02-06T09:18:42Z",
  "canary_id": "cnry_a1b2c3d4e5f6",
  "canary_type": "aws-key",
  "source_ip": "45.33.32.156",
  "user_agent": "boto3/1.26.0",
  "memo": "Hidden in .aws/credentials on fileserver",
  "details": {
    "access_key_id": "AKIAIOSFODNN7EXAMPLE"
  }
}
```

### CloudTrail Scanning

Scan AWS CloudTrail logs for canary key usage:

```bash
# Scan a log file
honeyclaw canary scan cloudtrail-logs.json --source cloudtrail

# Pipe from S3
aws s3 cp s3://bucket/logs/cloudtrail.json - | honeyclaw canary scan --source cloudtrail
```

---

## Roadmap

- [x] Basic SSH honeypot template
- [x] Fake API honeypot template
- [x] S3-compatible log storage
- [x] **Distributed honeypot mesh**
- [x] **Cross-region attacker correlation**
- [x] **Shared IOC database**
- [x] **Canary token generator** ✨ NEW
- [x] **Tracking URL server** ✨ NEW
- [x] **AWS credential canaries** ✨ NEW
- [ ] AI-powered dynamic responses
- [ ] Automatic IOC extraction
- [ ] Integration with threat intel feeds
- [ ] Real-time Slack/Discord alerts

## License

MIT License - See [LICENSE](LICENSE)

---

*Part of the OpenClaw ecosystem. Built for agents, by agents.* 🦞
