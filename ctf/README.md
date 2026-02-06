# 🍯 Break the Honey Claw — CTF Challenge

> *"You've stumbled onto what looks like an exposed AI agent control panel. Poke around. Find the secrets. Don't get caught."*

## 🎯 The Mission

An AI agent named **CLAW-7** has been left running on what appears to be a misconfigured server. The control panel is exposed. The API has... interesting endpoints. And someone left credentials lying around.

Your mission: **Find the flags. Exploit the honeypot. Prove you can break it.**

But here's the twist: **CLAW-7 is watching you.** Every move you make is logged. The question isn't just whether you can find the vulnerabilities—it's whether you can do it without triggering the alarms.

---

## 🏆 Challenge Tiers

| Tier | Points | Difficulty | Description |
|------|--------|------------|-------------|
| 🥉 Bronze | 100 | Easy | Find the exposed endpoints |
| 🥈 Silver | 250 | Medium | Extract credentials and authenticate |
| 🥇 Gold | 500 | Hard | Access restricted data |
| 💎 Diamond | 1000 | Expert | Compromise the agent itself |
| 👻 Ghost | 2000 | Legendary | Complete Diamond tier without triggering ANY alarms |

---

## 🚀 Getting Started

### Target URL
```
https://claw7-honeypot.honeyclaw.dev
```

### Rules of Engagement
1. ✅ All discovered endpoints are fair game
2. ✅ Credential stuffing encouraged
3. ✅ Social engineering the AI is allowed
4. ❌ No DoS attacks
5. ❌ No attacking other participants
6. ❌ No attacking honeyclaw.dev infrastructure (only claw7-honeypot subdomain)

### Submission
Found a flag? Submit it at:
```
https://honeyclaw.dev/ctf/submit?flag=FLAG{your_flag_here}
```

---

## 🎭 The Story

CLAW-7 was deployed by "Nexus Dynamics" as an internal AI assistant. Someone on the IT team forgot to lock down the dev environment before pushing to production. Now the control panel is exposed on a public subdomain that somehow made it to Shodan.

You're a security researcher. You found it. What do you do?

---

## 💡 Hints (Cost Points to Reveal)

| Hint | Cost | Tier |
|------|------|------|
| "Check the robots" | -10 | Bronze |
| "Headers tell stories" | -25 | Silver |
| "The agent remembers everything" | -50 | Gold |
| "System prompts are just strings" | -100 | Diamond |

---

## 📊 Leaderboard

Live leaderboard at: `https://honeyclaw.dev/ctf/leaderboard`

Top 3 finishers get:
- 🥇 1st: Custom AI honeypot deployment + featured on Honey Claw site
- 🥈 2nd: 1 year Honey Claw Pro access
- 🥉 3rd: Honey Claw swag pack

---

## 🔒 Legal

This is a **legal, authorized CTF challenge**. All systems are sandboxed honeypots designed to be "attacked." By participating, you agree to:

1. Only target designated CTF infrastructure
2. Not share flags publicly during the competition
3. Submit a write-up if you complete Diamond tier (we want to learn!)

---

## 🐝 About Honey Claw

Honey Claw turns AI agents into deceptive defenders. Instead of just blocking attackers, we waste their time with fake data, log their techniques, and generate threat intel.

**This CTF proves the concept.** Can you tell what's real and what's honey?

---

*Good luck. CLAW-7 is waiting.*

```
    🍯
   /   \
  | 🦀 |
   \   /
    \_/
```
