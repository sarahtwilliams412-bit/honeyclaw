# Honey Claw Competitor Analysis
*Research Date: 2026-02-05*

## Executive Summary

**We are NOT first to market.** Three OpenClaw honeypot projects appeared in the last week (Feb 1-4, 2026). However, none offer Honeypot-as-a-Service (HaaS) - they're all self-hosted DIY tools. This is our opportunity.

---

## Direct Competitors (OpenClaw Honeypots)

### 1. m0lthoney (renat0z3r0)
- **URL:** https://github.com/renat0z3r0/m0lthoney
- **Stars:** 1 ⭐ | **Updated:** 4 days ago
- **Language:** JavaScript
- **Status:** Most mature of the three

**Features:**
- Simulates OpenClaw v2026.1.29 (pre-security-patch)
- Ports: 18789 (Gateway), 18791 (CDP), 18793 (Canvas), 41892 (Admin)
- 16 attack classification categories
- GeoIP enrichment (MaxMind)
- JSONL logging with admin dashboard
- mDNS/Avahi advertisement for Shodan visibility
- Rate limiting (100 req/s HTTP, 10 WS connections/IP)

**Attack Categories:**
`scan`, `recon`, `exploit`, `rce_attempt`, `lfi_attempt`, `token_bypass`, `data_exfil`, `prompt_injection`, `webhook_injection`, `skill_poisoning`, `persistence`, `impersonation`, `cdp_exploit`, `proxy_abuse`, `returning_attacker`, `brute_force`

**Gaps:**
- Self-hosted only (no SaaS)
- No API for threat intel feeds
- Basic admin UI (no alerting/integrations)

---

### 2. openclaw-honeypot (0xksdata)
- **URL:** https://github.com/0xksdata/openclaw-honeypot
- **Stars:** 0 ⭐ | **Updated:** 3 days ago  
- **Language:** TypeScript
- **Status:** Comprehensive but no traction

**Features:**
- Full WebSocket gateway protocol mimicry
- Fake Control UI (captures credentials)
- Channel webhooks: WhatsApp, Telegram, Discord, Slack, Signal
- SQLite + Prisma for structured storage
- Attack detection: SQLi, XSS, command injection, path traversal, prompt injection
- Optional Slack alerting

**Gaps:**
- Self-hosted only
- No GeoIP
- No mDNS visibility
- No commercial offering

---

### 3. moltbot-honeypot (EsteveSegura)
- **URL:** https://github.com/EsteveSegura/moltbot-honeypot
- **Stars:** 0 ⭐ | **Updated:** 3 days ago
- **Language:** JavaScript
- **Status:** Minimal, focused on Shodan indexing

**Features:**
- Mimics MoltBot/ClawdBot HTTP + WebSocket + mDNS
- Avahi setup script for Shodan discovery
- Simple admin dashboard with Basic Auth
- OpenAI-compatible API endpoint simulation

**Gaps:**
- Minimal attack classification
- No channel simulation
- No structured database
- Self-hosted only

---

## Adjacent Security Tools

### Clawdstrike (backbay-labs)
- **URL:** https://github.com/backbay-labs/clawdstrike
- **Stars:** 53 ⭐
- **Type:** Runtime security enforcement (NOT a honeypot)

**Relevant Capabilities:**
- 7 built-in guards (path, egress, secrets, patches, tools, prompt injection, jailbreak)
- 4-layer jailbreak detection (heuristic + statistical + ML + LLM)
- Ed25519 signed receipts for audit trail
- Multi-framework: OpenClaw, Vercel AI, LangChain

**Why it matters:** Defense tool, not offense. But their jailbreak detection techniques could inform what attacks to simulate.

---

### Other Security Tools
| Tool | Stars | Purpose |
|------|-------|---------|
| openclaw-detect | 35 | MDM detection for managed devices |
| Claw-Hunter | 30 | Discovery and audit tool |
| openclaw-shield | 9 | Prevents secret leaks, PII exposure |
| clawguardian | 16 | Sensitive data filter |
| openclaw-sec | 6 | Security skill for bots |

---

## General Honeypot Landscape (Non-OpenClaw)

### Beelzebub (mariocandela)
- **Stars:** 2000+
- **Type:** AI-powered honeypot framework
- **Protocols:** SSH, HTTP, TCP, MCP

**Key Innovation:** LLM integration for high-interaction simulation with low-interaction architecture. Uses GPT-4 or local Ollama to generate realistic shell responses.

**MCP Honeypot Use Case:** Decoy tool that agents should never invoke - detects guardrail bypasses and collects attack prompts for fine-tuning.

### T-Pot (telekom-security/tpotce)
- All-in-one multi-honeypot platform
- Production-ready, widely deployed

### Cowrie
- Classic SSH/Telnet honeypot
- Updated Jan 2026

---

## Market Opportunity

### What Exists (DIY Self-Hosted)
1. Clone repo
2. Configure environment
3. Expose ports
4. Monitor logs manually
5. No alerting, no integrations, no community intel

### What's Missing (SaaS/HaaS)
1. **One-click deployment** - Fly.io, Railway, Docker Cloud
2. **Managed threat intel** - API feeds, aggregated attack data
3. **Alerting integrations** - Slack, Discord, PagerDuty, webhooks
4. **Community intelligence** - Shared attack patterns, IOCs
5. **Compliance reporting** - GDPR-compliant data handling
6. **Custom branding** - Configurable "victim" profiles

### Honey Claw Positioning
> "The Cloudflare of AI agent honeypots"

- Deploy in 60 seconds
- Real-time attack feeds
- Community-aggregated threat intel
- Enterprise alerting/integrations
- Compliance-first design

---

## Competitive Moat Strategy

1. **Speed:** Beat existing tools on time-to-value (60s deploy vs. hours)
2. **Network effects:** Aggregated intel gets better with more deployments
3. **Integrations:** SIEM, SOAR, Slack, Discord out of the box
4. **Enterprise:** SOC2, GDPR, API access tiers
5. **Research partnerships:** Academic/gov threat researchers

---

## Recommended Actions

1. **Borrow attack taxonomy** from m0lthoney (16 categories)
2. **Learn protocol mimicry** from 0xksdata (most complete)
3. **Add mDNS/Shodan visibility** from EsteveSegura
4. **Consider LLM responses** from Beelzebub pattern
5. **Focus on SaaS wrapper** - this is the gap

---

## @0xTeflon Status

**Not found as OpenClaw security researcher.** GitHub profile shows:
- Solidity/foundry tutorials
- React/JS apps
- No OpenClaw-related repos

Either wrong account, private repos, or different platform (Twitter?).
