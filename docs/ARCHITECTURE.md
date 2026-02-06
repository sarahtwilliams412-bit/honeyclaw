# Honey Claw Architecture

## Live Deployment

**Current Production:** `149.248.202.23:8022` (Fly.io, honeyclaw-ssh app)

See [DEPLOYMENT.md](./DEPLOYMENT.md) for setup details.

---

## Overview

Honey Claw is designed as a modular honeypot framework that integrates with OpenClaw agents for AI-powered threat detection and response.

## System Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                         OpenClaw Agent                              │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    Honey Claw Skill                           │  │
│  │                                                               │  │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐ │  │
│  │  │  Deploy   │  │  Monitor  │  │  Analyze  │  │  Respond  │ │  │
│  │  │  Manager  │  │  Service  │  │  (AI)     │  │  Engine   │ │  │
│  │  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘ │  │
│  └────────┼──────────────┼──────────────┼──────────────┼────────┘  │
└───────────┼──────────────┼──────────────┼──────────────┼───────────┘
            │              │              │              │
            ▼              ▼              ▼              ▼
     ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
     │  Docker  │   │  Log     │   │  MITRE   │   │  Alert   │
     │  Engine  │   │  Store   │   │  ATT&CK  │   │  System  │
     └──────────┘   └──────────┘   └──────────┘   └──────────┘
            │
            ▼
     ┌─────────────────────────────────────────┐
     │           Honeypot Network               │
     │  ┌─────────┐ ┌─────────┐ ┌─────────┐   │
     │  │basic-ssh│ │fake-api │ │ent-sim  │   │
     │  │   :22   │ │  :8080  │ │ :multi  │   │
     │  └─────────┘ └─────────┘ └─────────┘   │
     └─────────────────────────────────────────┘
```

## Components

### 1. Deploy Manager

Handles honeypot lifecycle:
- Template selection and validation
- Docker container creation
- Network configuration
- Resource allocation
- Health monitoring

### 2. Monitor Service

Real-time log aggregation:
- Collects logs from all active honeypots
- Normalizes event format
- Streams to storage backends
- Maintains event buffer for analysis

### 3. Analyze (AI-Powered)

Threat intelligence processing:
- MITRE ATT&CK technique mapping
- IOC extraction (IPs, domains, hashes)
- Attacker profiling
- Pattern correlation across honeypots
- Natural language threat summaries

### 4. Respond Engine

Automated response capabilities:
- Alert generation
- Firewall rule suggestions
- Threat feed updates
- Adaptive honeypot configuration

## Data Flow

```
Attacker → Honeypot Container → Event Logger → Log Aggregator
                                                     │
                                    ┌────────────────┴────────────────┐
                                    ▼                                 ▼
                              S3 Storage                        AI Analysis
                                    │                                 │
                                    └────────────────┬────────────────┘
                                                     ▼
                                              Alert/Response
```

## Template System

Each template defines:

```yaml
# Template manifest
name: template-name
version: 1.0.0
interaction_level: low|medium|high

# Container configuration
resources:
  memory: 64m
  cpu: 0.1

# Service configuration
settings:
  service_specific_config: value

# Logging configuration
logging:
  format: json
  mitre:
    tactics: [TA0001]
    techniques: [T1078]
```

## Isolation Model

### Container Isolation

Each honeypot runs in an isolated Docker container with:

- **Read-only root filesystem** - Prevents persistent modifications
- **No new privileges** - Blocks privilege escalation
- **Dropped capabilities** - Minimal Linux capabilities
- **Resource limits** - CPU, memory, process limits
- **Network isolation** - Dedicated honeypot network

### Network Isolation

```
┌─────────────────────────────────────────────────────────────┐
│                     Host Network                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              honeyclaw-net (Bridge)                  │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐            │    │
│  │  │  HP-1   │  │  HP-2   │  │  HP-3   │  No ICC    │    │
│  │  └────┬────┘  └────┬────┘  └────┬────┘            │    │
│  │       │            │            │                  │    │
│  │       └────────────┴────────────┘                  │    │
│  │                    │                               │    │
│  │              Port Mapping Only                     │    │
│  │              (No outbound)                         │    │
│  └─────────────────────┼───────────────────────────────┘    │
│                        │                                     │
│                   External Access                            │
└─────────────────────────────────────────────────────────────┘
```

## Log Schema

All events follow a standardized JSON schema:

```json
{
  "version": "1.0",
  "timestamp": "ISO8601",
  "honeypot": {
    "id": "string",
    "template": "string",
    "container_id": "string"
  },
  "source": {
    "ip": "string",
    "port": "number",
    "geo": {}
  },
  "event": {
    "type": "string",
    "protocol": "string",
    "payload": {}
  },
  "analysis": {
    "mitre_tactics": [],
    "mitre_techniques": [],
    "threat_score": "number",
    "iocs": []
  }
}
```

## Storage Backends

### S3-Compatible

- AWS S3
- MinIO
- Cloudflare R2
- DigitalOcean Spaces

### Local

- JSON files
- SQLite database

## Integration Points

### OpenClaw Agent

```javascript
// Deploy honeypot
await honeyclaw.deploy({
  template: 'basic-ssh',
  name: 'trap-01',
  port: 2222
});

// Stream events
honeyclaw.on('event', async (event) => {
  if (event.analysis.threat_score > 0.8) {
    await notifySecurityTeam(event);
  }
});
```

### SIEM Integration

Events can be forwarded to:
- Splunk
- Elastic Security
- Azure Sentinel
- Chronicle

### Threat Intel Feeds

IOC export to:
- STIX/TAXII
- MISP
- OpenCTI
