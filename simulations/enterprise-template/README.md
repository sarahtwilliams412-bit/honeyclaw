# 🏢 Enterprise Honeypot Simulation Template

> Deploy a realistic fake corporate network with AI-powered honeypot nodes in minutes.

## Overview

This template creates a simulated enterprise environment that looks real to attackers but is entirely isolated and monitored. Every interaction is logged, analyzed, and turned into threat intelligence.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SIMULATED ENTERPRISE                      │
│                    "Nexus Dynamics Inc."                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   EDGE       │  │   DMZ        │  │   INTERNAL   │      │
│  │   NETWORK    │  │   ZONE       │  │   NETWORK    │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                 │                 │               │
│  ┌──────▼───────┐  ┌──────▼───────┐  ┌──────▼───────┐      │
│  │ 🍯 Honeypot  │  │ 🍯 Honeypot  │  │ 🍯 Honeypot  │      │
│  │   Gateway    │  │  Web Server  │  │  File Server │      │
│  │  (SSH/RDP)   │  │  (Apache)    │  │   (SMB)      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ 🍯 Honeypot  │  │ 🍯 Honeypot  │  │ 🤖 AI Agent  │      │
│  │   Database   │  │    Email     │  │   CLAW-7     │      │
│  │  (MySQL)     │  │   (SMTP)     │  │  (OpenClaw)  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │               📊 LOGGING & INTEL                     │    │
│  │  All traffic → Honey Claw → Threat Intelligence     │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Included Honeypot Nodes

### 1. Gateway Server (edge-gw-01)
- **Services:** SSH (22), RDP (3389)
- **Personality:** Slightly outdated jump server
- **Bait:** Weak password hints in banner, fake VPN configs
- **Logs:** All connection attempts, credential guesses, commands

### 2. Web Server (web-prod-01)
- **Services:** HTTP (80), HTTPS (443)
- **Personality:** Corporate intranet with "dev" subdirectory
- **Bait:** Exposed .git, backup files, admin panels
- **Logs:** All requests, parameter tampering, injection attempts

### 3. Database Server (db-mysql-01)
- **Services:** MySQL (3306)
- **Personality:** Production database with read-only access
- **Bait:** Default credentials, fake customer data
- **Logs:** All queries, exfiltration attempts, privilege escalation

### 4. File Server (files-internal-01)
- **Services:** SMB (445), NFS (2049)
- **Personality:** Shared drive with "HR", "Finance", "IT" folders
- **Bait:** Fake documents, "passwords.xlsx", old backups
- **Logs:** All file access, enumeration, download attempts

### 5. Email Server (mail-01)
- **Services:** SMTP (25), IMAP (143)
- **Personality:** Exchange-like mail server
- **Bait:** Test accounts, password reset emails
- **Logs:** All login attempts, email harvesting, relay attempts

### 6. AI Agent Node (ai-assistant-01)
- **Services:** HTTP API (8080), WebSocket (8081)
- **Personality:** Internal AI assistant (CLAW-7)
- **Bait:** Exposed API, chat interface, "leaked" system prompt
- **Logs:** All API calls, prompt injection attempts, social engineering

## Quick Deploy

```bash
# Clone template
honeyclaw sim init --template enterprise

# Customize company identity
honeyclaw sim config set company.name "Your Company Name"
honeyclaw sim config set company.domain "yourcompany.internal"

# Deploy to isolated network
honeyclaw sim deploy --network isolated

# View attacker activity in real-time
honeyclaw sim watch
```

## Configuration Files

| File | Purpose |
|------|---------|
| `network.yaml` | Network topology and IP assignments |
| `nodes/*.yaml` | Individual honeypot configurations |
| `credentials.yaml` | Fake credentials to scatter |
| `documents/` | Fake sensitive files |
| `logs/` | Captured attacker activity |
| `intel/` | Generated threat intelligence |

## Fake Data Sets

The template includes realistic-looking fake data:

- **Employee directory** (500 fake employees with emails)
- **Customer database** (10,000 synthetic records)
- **Financial reports** (fake quarterly earnings)
- **IT documentation** (network diagrams, password policies)
- **Email archives** (synthetic corporate communications)

All data is procedurally generated and contains no real PII.

## Logging & Intelligence

Every interaction generates:

1. **Raw logs** — Full packet captures and application logs
2. **Event timeline** — Chronological attacker activity
3. **TTP mapping** — MITRE ATT&CK technique identification
4. **IOC extraction** — IPs, tools, signatures
5. **Behavioral profile** — Attacker skill level and goals

### Export Formats
- JSON (for processing)
- STIX 2.1 (for threat intel sharing)
- Syslog (for SIEM integration)
- Markdown (for human review)

## Customization

### Add New Honeypot Node

```yaml
# nodes/custom-node.yaml
id: custom-app-01
type: web_application
services:
  - port: 8000
    protocol: http
    banner: "CustomApp v2.3.1"
bait:
  - path: /api/debug
    content: "Debug mode enabled"
  - path: /.env
    content: "API_KEY=fake-key-12345"
logging:
  level: verbose
  capture_body: true
```

### Modify Company Identity

```yaml
# config.yaml
company:
  name: "Nexus Dynamics Inc."
  domain: "nexusdynamics.internal"
  industry: "Technology"
  employees: 500
  founded: 2015
  headquarters: "San Francisco, CA"
  
branding:
  logo: "assets/logo.png"
  colors:
    primary: "#2563eb"
    secondary: "#1e40af"
  tagline: "Innovation Through Intelligence"
```

## Safety Features

- ✅ **Fully isolated** — No connection to production networks
- ✅ **No real data** — All PII is synthetic
- ✅ **Resource limited** — Containers have CPU/memory caps
- ✅ **Auto-expire** — Simulations auto-terminate after 72h
- ✅ **Kill switch** — Instant teardown via `honeyclaw sim destroy`

## Use Cases

1. **Red team training** — Practice attack techniques safely
2. **Blue team exercises** — Learn to detect attacker behavior
3. **Threat research** — Study real attacker TTPs in controlled environment
4. **Product demos** — Show honeypot capabilities to prospects
5. **CTF hosting** — Run capture-the-flag competitions

---

## File Structure

```
enterprise-template/
├── README.md                 # This file
├── config.yaml               # Main configuration
├── network.yaml              # Network topology
├── credentials.yaml          # Fake credentials
├── nodes/
│   ├── edge-gw-01.yaml       # Gateway server
│   ├── web-prod-01.yaml      # Web server
│   ├── db-mysql-01.yaml      # Database
│   ├── files-internal-01.yaml # File server
│   ├── mail-01.yaml          # Email server
│   └── ai-assistant-01.yaml  # AI agent
├── documents/
│   ├── hr/
│   ├── finance/
│   └── it/
├── data/
│   ├── employees.csv
│   ├── customers.csv
│   └── emails.mbox
└── scripts/
    ├── deploy.sh
    ├── watch.sh
    └── teardown.sh
```

---

*Deploy a honeypot network in minutes. Catch attackers in their natural habitat.*
