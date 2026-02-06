# Honey Claw Research Summary
*Completed: 2026-02-05 17:45 PST*

## Key Findings

### 🚨 Competition Alert
**We are NOT first to market for OpenClaw honeypots.** Three projects appeared in the past week:

| Project | Stars | Language | Last Updated |
|---------|-------|----------|--------------|
| m0lthoney | 1 ⭐ | JavaScript | 4 days ago |
| openclaw-honeypot | 0 | TypeScript | 3 days ago |
| moltbot-honeypot | 0 | JavaScript | 3 days ago |

**However:** All are self-hosted DIY tools. None offer SaaS/HaaS (Honeypot-as-a-Service).

### ✅ Market Opportunity Confirmed
The gap is **managed honeypot infrastructure**:
- One-click deployment
- Aggregated threat intelligence
- Enterprise integrations (SIEM, Slack, etc.)
- Compliance handling (GDPR retention)

### 📋 Attack Taxonomy (16 Categories)
Borrowed from m0lthoney:
`scan`, `recon`, `exploit`, `rce_attempt`, `lfi_attempt`, `token_bypass`, `data_exfil`, `prompt_injection`, `webhook_injection`, `skill_poisoning`, `persistence`, `impersonation`, `cdp_exploit`, `proxy_abuse`, `returning_attacker`, `brute_force`

### 🛡️ Threat Model
- **Primary threats:** Opportunistic scanners, targeted attackers, security researchers
- **Emerging threat:** AI agent exploitation specialists (prompt injection experts)
- **Isolation required:** Egress blocked, separate cloud account, no production credentials

### 🔧 Technical Patterns
From competitor analysis:
- Port 18789 (Gateway), 18791 (CDP), 18793 (Canvas)
- WebSocket protocol mimicry documented
- mDNS/Avahi for Shodan visibility
- Accept all auth, log everything
- Canary tokens for leak detection

### ❌ @0xTeflon
GitHub profile found but **no OpenClaw security research**. Contains only:
- Solidity/foundry tutorials
- React/JS apps
- Merkle tree implementations

Either wrong account, private repos, or different platform.

---

## Deliverables Created

1. **`competitor-analysis.md`** - Deep dive on 3 honeypots + security tools
2. **`threat-model.md`** - Attack simulation matrix, isolation requirements, legal considerations
3. **`safe-mimicry-patterns.md`** - Protocol specs, code patterns, implementation checklist

---

## Recommended Next Steps

1. **Copy attack taxonomy** from m0lthoney (proven categories)
2. **Focus on SaaS wrapper** - this is the differentiation
3. **MVP scope:** Gateway + WebSocket + basic logging + Fly.io deploy
4. **Skip LLM shell simulation** for MVP (adds complexity)
5. **Add mDNS later** for Shodan visibility

---

## Useful Repos to Study

| Repo | Why |
|------|-----|
| `renat0z3r0/m0lthoney` | Best attack taxonomy, most complete |
| `0xksdata/openclaw-honeypot` | Full protocol spec, TypeScript |
| `mariocandela/beelzebub` | LLM honeypot patterns, MCP trap design |
| `backbay-labs/clawdstrike` | Defense patterns to inform offense |

---

## Blockers

- **Web search unavailable** (no Brave API key) - used direct URL fetching instead
- **@0xTeflon research** - couldn't find OpenClaw work, may need Twitter/X search

---

*Research complete. Ready for implementation phase.*
