<p align="center">
  <img src="assets/honeyclaw-logo.png" alt="Honey Claw" width="200"/>
</p>

<h1 align="center">🍯 Honey Claw</h1>

<p align="center">
  <strong>AI-Powered Honeypot-as-a-Service</strong><br>
  Deploy intelligent decoy systems. Catch attackers. Generate threat intelligence.
</p>

<p align="center">
  <a href="https://honeyclaw.io">Website</a> •
  <a href="https://docs.honeyclaw.io">Docs</a> •
  <a href="https://ctf.honeyclaw.io">CTF Challenge</a> •
  <a href="https://discord.gg/honeyclaw">Discord</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-beta-yellow" alt="Status: Beta"/>
  <img src="https://img.shields.io/github/license/honeyclaw/honeyclaw" alt="License"/>
  <img src="https://img.shields.io/github/stars/honeyclaw/honeyclaw?style=social" alt="Stars"/>
</p>

---

## What is Honey Claw?

Honey Claw lets you deploy **AI-powered honeypots** in seconds. Watch attackers interact with fake vulnerable systems while our AI keeps them engaged and extracts maximum intelligence.

```
┌─────────────────────────────────────────────────────────────┐
│  Attacker                                                    │
│     │                                                        │
│     ▼                                                        │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │  SSH Honey  │    │  Web Honey  │    │  DB Honey   │      │
│  │    pot      │    │    pot      │    │    pot      │      │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘      │
│         │                  │                  │              │
│         └────────────┬─────┴──────────────────┘              │
│                      ▼                                       │
│              ┌──────────────┐                                │
│              │   🤖 Claw    │  ← AI analyzes & responds      │
│              │   AI Engine  │                                │
│              └──────┬───────┘                                │
│                     ▼                                        │
│              ┌──────────────┐                                │
│              │    📊 You    │  ← Real-time dashboard         │
│              │  Dashboard   │                                │
│              └──────────────┘                                │
└─────────────────────────────────────────────────────────────┘
```

## ✨ Features

### 🚀 One-Click Deployment
Deploy honeypots instantly. No infrastructure setup. No maintenance burden.

### 🤖 AI-Powered Responses
Our AI ("Claw") simulates realistic system behavior, keeping attackers engaged longer for better intelligence.

### 🔒 Sandboxed & Safe
Every honeypot runs in isolated containers. Attackers can't escape. Your real systems stay protected.

### 📊 Automated Intelligence
Get plain-English threat reports. Understand attacker TTPs without being a forensics expert.

### 🎭 Multiple Personalities
- **SSH Server** - Watch brute force attacks and credential stuffing
- **Web Application** - Detect SQLi, XSS, and web exploits
- **Database** - Catch data exfiltration attempts
- **API Endpoints** - Monitor unauthorized API access
- **Custom** - Build your own honeypot persona

## 🏁 Quick Start

### Cloud (Recommended)
```bash
# Sign up at honeyclaw.io, then:
npx honeyclaw deploy --template ssh-basic
```

### Self-Hosted
```bash
# Clone the repo
git clone https://github.com/honeyclaw/honeyclaw.git
cd honeyclaw

# Start with Docker
docker-compose up -d

# Access dashboard at http://localhost:3000
```

### Configuration
```yaml
# honeyclaw.yaml
honeypots:
  - name: "web-decoy"
    type: "web"
    port: 8080
    ai_personality: "confused-sysadmin"
    
  - name: "ssh-trap" 
    type: "ssh"
    port: 2222
    ai_personality: "default"
    
alerting:
  slack_webhook: "https://hooks.slack.com/..."
  email: "security@yourcompany.com"
```

## 📈 Dashboard Preview

```
┌────────────────────────────────────────────────────────────────┐
│ 🍯 HONEY CLAW                                    [Live ●]      │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Active Honeypots: 3        Attacks Today: 147                 │
│  ═══════════════════        ═══════════════════                │
│  [████████████░░░░] 3/5     [████████████████░] 147            │
│                                                                │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ LIVE ATTACK FEED                                        │  │
│  ├─────────────────────────────────────────────────────────┤  │
│  │ 17:32:01  SSH    185.*.*.42    Brute force (admin/admin)│  │
│  │ 17:31:58  WEB    103.*.*.91    SQLi attempt detected    │  │
│  │ 17:31:45  SSH    185.*.*.42    Connection established   │  │
│  │ 17:31:12  WEB    45.*.*.203    Directory traversal      │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                                │
│  TOP ATTACKER IPs          TOP ATTACK TYPES                   │
│  1. 185.*.*.42 (34)        1. Brute Force (67%)               │
│  2. 103.*.*.91 (28)        2. Web Exploits (21%)              │
│  3. 45.*.*.203 (19)        3. Recon (12%)                     │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

## 🎯 Use Cases

| Who | Why |
|-----|-----|
| **Security Teams** | Test detection capabilities with real attack data |
| **Researchers** | Study attacker TTPs in controlled environments |
| **Educators** | Teach security concepts with live demonstrations |
| **Startups** | Enterprise-grade threat intel on a startup budget |
| **CTF Players** | Practice defense and learn attacker techniques |

## 🧠 How the AI Works

Claw uses large language models fine-tuned on:
- Real sysadmin interactions
- Common attack/response patterns  
- Deceptive engagement techniques

The result: Attackers can't tell they're talking to a machine.

```
Attacker: cat /etc/passwd
Claw:     root:x:0:0:root:/root:/bin/bash
          daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
          admin:x:1000:1000:System Administrator:/home/admin:/bin/bash
          
Attacker: sudo cat /etc/shadow
Claw:     [sudo] password for user: 
          Sorry, try again.
          [sudo] password for user: 
          admin is not in the sudoers file. This incident will be reported.
          
# Meanwhile, you see everything in your dashboard 📊
```

## 🔐 Security Model

| Layer | Protection |
|-------|------------|
| **Isolation** | Each honeypot in separate container with no network access to others |
| **Containment** | Malware can't escape sandbox; auto-quarantined |
| **No Real Data** | Honeypots never connect to production systems |
| **Audit Trail** | Every action logged for forensics |

## 🪙 $HONEYCLAW Token (Coming Soon)

We're building a token economy for threat intelligence:

- **Earn** tokens by contributing anonymized attack data
- **Spend** tokens on premium analysis features
- **Stake** for governance rights
- **Trade** intelligence on decentralized marketplace

*Not financial advice. Token not yet live.*

## 📖 Documentation

- [Getting Started Guide](https://docs.honeyclaw.io/quickstart)
- [Honeypot Templates](https://docs.honeyclaw.io/templates)
- [AI Personality Customization](https://docs.honeyclaw.io/ai)
- [API Reference](https://docs.honeyclaw.io/api)
- [Self-Hosting Guide](https://docs.honeyclaw.io/self-host)

## 🎮 Try It Now: CTF Challenge

Think you can outsmart our AI?

**[→ ctf.honeyclaw.io](https://ctf.honeyclaw.io)**

Find the hidden flags. Determine what's real vs. simulated. Top scorers get early access + swag.

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development setup
git clone https://github.com/honeyclaw/honeyclaw.git
cd honeyclaw
npm install
npm run dev
```

## 📜 License

MIT License. See [LICENSE](LICENSE) for details.

## ⚠️ Legal Disclaimer

Honeypots are **legal defensive tools** when deployed on infrastructure you own or have authorization to test. Do not use Honey Claw for:
- Deploying on systems without authorization
- Entrapping individuals
- Any illegal purpose

See our [Legal FAQ](https://docs.honeyclaw.io/legal) for details.

---

<p align="center">
  <strong>Built with 🍯 by the Honey Claw team</strong><br>
  <a href="https://twitter.com/honeyclaw">Twitter</a> •
  <a href="https://discord.gg/honeyclaw">Discord</a> •
  <a href="mailto:hello@honeyclaw.io">Contact</a>
</p>
