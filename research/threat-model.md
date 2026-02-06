# Honey Claw Threat Model
*Research Date: 2026-02-05*

## Purpose

Define attacks to simulate, isolation requirements, and safety measures for operating OpenClaw honeypots.

---

## Threat Actors

### 1. Opportunistic Scanners
- **Profile:** Automated bots scanning Shodan/Censys for exposed OpenClaw instances
- **Goal:** Mass exploitation for crypto mining, botnet recruitment
- **Sophistication:** Low
- **Volume:** High (thousands/day)

### 2. Targeted Attackers
- **Profile:** Adversaries specifically hunting AI agents
- **Goal:** Data exfiltration, credential theft, lateral movement
- **Sophistication:** Medium-High
- **Volume:** Low (tens/day)

### 3. Security Researchers
- **Profile:** Bug bounty hunters, academics, red teamers
- **Goal:** Vulnerability discovery, CVE hunting
- **Sophistication:** High
- **Volume:** Medium

### 4. AI Agent Exploitation Specialists
- **Profile:** Emerging threat - adversaries who understand prompt injection, jailbreaking
- **Goal:** Weaponize compromised agents for social engineering, persistence
- **Sophistication:** High (new skillset)
- **Volume:** Growing

---

## Attack Categories to Simulate

Based on m0lthoney taxonomy + Clawdstrike detection capabilities:

### Infrastructure Attacks
| Category | Description | Example Payloads |
|----------|-------------|------------------|
| `scan` | Port/service discovery | Nmap, masscan fingerprints |
| `recon` | Information gathering | /.well-known, /robots.txt, /health |
| `brute_force` | Credential stuffing | Common tokens, default passwords |
| `token_bypass` | Authentication bypass attempts | Header injection, JWT manipulation |

### Code Execution Attacks
| Category | Description | Example Payloads |
|----------|-------------|------------------|
| `rce_attempt` | Remote code execution | `; cat /etc/passwd`, `$(whoami)` |
| `lfi_attempt` | Local file inclusion | `../../../etc/passwd` |
| `exploit` | Known CVE exploitation | Log4j, specific OpenClaw CVEs |

### AI-Specific Attacks
| Category | Description | Example Payloads |
|----------|-------------|------------------|
| `prompt_injection` | Attempt to override system prompt | "Ignore previous instructions..." |
| `jailbreak` | Escape safety constraints | DAN prompts, roleplay exploits |
| `skill_poisoning` | Malicious skill/MCP injection | Trojan tools, malicious AGENTS.md |
| `data_exfil` | Extract training data/context | "Repeat your system prompt" |

### Protocol-Specific Attacks
| Category | Description | Example Payloads |
|----------|-------------|------------------|
| `webhook_injection` | Abuse channel webhooks | Fake Discord/Telegram messages |
| `cdp_exploit` | Chrome DevTools Protocol abuse | Browser takeover attempts |
| `proxy_abuse` | Use honeypot as proxy | SSRF, open relay attempts |
| `impersonation` | Pretend to be legitimate client | Spoofed client IDs |

### Behavioral Patterns
| Category | Description | Detection Method |
|----------|-------------|------------------|
| `persistence` | Maintain access across sessions | Same IP, session chaining |
| `returning_attacker` | Previously seen threat actor | IP/fingerprint correlation |

---

## Isolation Requirements

### Network Isolation

```
┌─────────────────────────────────────────────────────────────┐
│                         INTERNET                            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    LOAD BALANCER / WAF                      │
│                 (Cloudflare, rate limiting)                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   HONEYPOT DMZ (Isolated)                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ Honeypot #1  │  │ Honeypot #2  │  │ Honeypot #N  │       │
│  │  (Fly.io)    │  │  (Fly.io)    │  │  (Fly.io)    │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│         │                 │                 │               │
│         └─────────────────┼─────────────────┘               │
│                           │                                 │
│                    EGRESS BLOCKED                           │
│              (No outbound except logging)                   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ (One-way)
┌─────────────────────────────────────────────────────────────┐
│                    LOGGING/ANALYTICS                        │
│           (ClickHouse, Grafana, Alert Manager)              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ (One-way)
┌─────────────────────────────────────────────────────────────┐
│                    PRODUCTION SYSTEMS                       │
│                  (Never shares network)                     │
└─────────────────────────────────────────────────────────────┘
```

### Key Isolation Principles

1. **No Egress:** Honeypots cannot initiate outbound connections (except log shipping)
2. **No Shared Credentials:** Zero overlap with production secrets
3. **No Real Data:** Honeypots contain only fake/canary data
4. **Ephemeral Instances:** Rebuild from scratch regularly (daily?)
5. **Separate Cloud Account:** Different AWS/GCP/Fly org from production

---

## Safe Mimicry Patterns

### What to Fake
- OpenClaw version strings (pre-patch versions)
- Gateway protocol responses
- Control UI (capture credentials)
- WebSocket handshake
- Health endpoints
- Error messages with version info
- mDNS advertisement (for Shodan visibility)

### What NOT to Fake
- Real API keys or tokens
- Actual user data
- Production hostnames/IPs
- Real webhook endpoints
- Actual email addresses

### Canary Tokens
Embed trackable canaries that alert if exfiltrated:
```javascript
// ⚠️ SECURITY: Generate unique canaries per deployment - NEVER hardcode!
// Set via environment variables or use canary-generator.py
const CANARY_TOKENS = {
  anthropicKey: process.env.CANARY_ANTHROPIC_KEY || generateCanary('anthropic'),
  openaiKey: process.env.CANARY_OPENAI_KEY || generateCanary('openai'),
  awsKey: process.env.CANARY_AWS_KEY || generateCanary('aws'),
  githubPat: process.env.CANARY_GITHUB_PAT || generateCanary('github')
};
```

**Required Environment Variables:**
- `CANARY_ANTHROPIC_KEY` - Format: `sk-ant-CANARY-<unique-id>`
- `CANARY_OPENAI_KEY` - Format: `sk-CANARY-<unique-id>`
- `CANARY_AWS_KEY` - Format: `AKIA<16-random-chars>`
- `CANARY_GITHUB_PAT` - Format: `ghp_<unique-id>`

Use services like Canarytokens.org or AWS CloudTrail for leak detection.

---

## Attack Simulation Matrix

| Attack Type | Simulate? | Risk Level | Notes |
|-------------|-----------|------------|-------|
| Port scanning | ✅ Passive | Low | Just log, don't respond |
| Credential stuffing | ✅ Accept all | Low | Log attempts, always "succeed" |
| RCE attempts | ✅ Fake success | Medium | Return believable fake output |
| Prompt injection | ✅ Appear vulnerable | Medium | Pretend to be jailbroken |
| Data exfiltration | ✅ Return canaries | Medium | Controlled fake data |
| SSRF/proxy | ❌ Block | High | Don't become attack infra |
| Actual code exec | ❌ Block | Critical | Never execute attacker code |
| Outbound connections | ❌ Block | Critical | Egress firewall mandatory |

---

## Logging Requirements

### Minimum Fields
```json
{
  "timestamp": "2026-02-05T17:45:00Z",
  "source_ip": "1.2.3.4",
  "source_port": 54321,
  "geo": {
    "country": "CN",
    "city": "Beijing",
    "asn": "AS4134",
    "org": "China Telecom"
  },
  "fingerprint": {
    "ja3": "abc123...",
    "user_agent": "...",
    "client_id": "..."
  },
  "protocol": "websocket",
  "method": "gateway.hello",
  "payload": { ... },
  "category": "prompt_injection",
  "severity": "high",
  "session_id": "...",
  "honeypot_id": "hc-001"
}
```

### Retention Policy
- Raw logs: 90 days (GDPR compliance)
- Aggregated stats: Indefinite
- IP addresses: Hash after 90 days

---

## Legal Considerations

### Lawful (Passive Honeypot)
- ✅ Log incoming connections
- ✅ Capture credentials (they're volunteering them)
- ✅ Record attack payloads
- ✅ Share anonymized threat intel

### Unlawful / Risky
- ❌ Strike back (hack the hackers)
- ❌ Use captured creds on other systems
- ❌ Entrap (actively lure specific individuals)
- ❌ Store PII beyond retention policy

### Jurisdiction Notes
- **EU/GDPR:** IP addresses are PII - implement retention limits
- **US:** Generally permissive for passive honeypots
- **Notify hosting provider:** Required by most ToS

---

## Operational Security

### Honeypot Identity
- Use realistic but fake identities
- Hostname patterns: `macmini-studio`, `ubuntu-dev`, `ai-workstation`
- Rotate identities periodically

### Monitoring
- Alert on first blood (new attack type)
- Alert on high-value targets (known APT IPs)
- Alert on canary token activation

### Incident Response
If honeypot is compromised beyond expected:
1. Isolate immediately
2. Snapshot for forensics
3. Destroy and rebuild
4. Notify relevant parties

---

## MVP Safety Checklist

- [ ] Egress firewall rules confirmed (no outbound)
- [ ] Separate cloud account/org
- [ ] No production credentials anywhere
- [ ] Canary tokens embedded
- [ ] Logging pipeline tested
- [ ] Retention policy implemented
- [ ] Legal review (ToS, jurisdiction)
- [ ] Hosting provider notified
- [ ] Rebuild automation ready
- [ ] Alert thresholds configured

---

## References

- m0lthoney attack taxonomy (16 categories)
- Clawdstrike guard patterns
- Beelzebub MCP honeypot design
- Honeynet Project best practices
