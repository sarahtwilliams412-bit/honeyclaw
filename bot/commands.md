# Honey Claw Bot - Command Specification

## Command Reference

---

### `/start`

**Purpose:** Welcome new users, explain the service

**Trigger:** First interaction or explicit `/start`

**Response:**
```
🍯 Welcome to Honey Claw!

Deploy cloud honeypots in seconds. Catch attackers, collect intel.

What we offer:
• SSH honeypots - Catch brute force attacks
• Web honeypots - Trap scanners and bots  
• MySQL honeypots - Lure database attackers

Commands:
/deploy <template> - Launch a honeypot
/status - Check your deployments
/logs - View recent attacks
/pricing - See plans & payment

Ready to set a trap? Try: /deploy ssh
```

**State:** None required

---

### `/deploy <template>`

**Purpose:** Deploy a new honeypot instance

**Arguments:**
- `template` (required): One of `ssh`, `web`, `mysql`

**Flow:**
1. Validate template name
2. Check user has available slots (MVP: 1 free)
3. Queue deployment request
4. Return confirmation with ETA

**Response (success):**
```
🚀 Deploying SSH honeypot...

Template: ssh (Cowrie-based)
Region: auto (nearest)
Status: Queued

You'll receive a notification when ready (~2 min).

Track progress: /status
```

**Response (invalid template):**
```
❌ Unknown template: "foobar"

Available templates:
• ssh - SSH honeypot (port 22)
• web - Web honeypot (port 80/443)
• mysql - MySQL honeypot (port 3306)

Try: /deploy ssh
```

**Response (limit reached):**
```
⚠️ You've reached your honeypot limit.

Current plan: Free (1 honeypot)
Active: 1/1

Upgrade for more: /pricing
```

**State:** Creates deployment record

---

### `/status`

**Purpose:** Show user's active honeypots and their status

**Response (has deployments):**
```
📊 Your Honeypots

┌─ ssh-7a3b ─────────────────┐
│ Type: SSH (Cowrie)         │
│ IP: 142.93.xx.xx           │
│ Status: 🟢 Active          │
│ Uptime: 2h 34m             │
│ Attacks: 47 today          │
└────────────────────────────┘

Total attacks captured: 1,247
Data exported: 12.4 MB

/logs - View recent activity
```

**Response (no deployments):**
```
📊 No Active Honeypots

You haven't deployed any honeypots yet.

Get started: /deploy ssh
```

**State:** Reads user's deployment records

---

### `/logs`

**Purpose:** Show recent attack activity

**Arguments (optional):**
- `count` - Number of logs to show (default: 5, max: 20)

**Response:**
```
📜 Recent Attacks (ssh-7a3b)

[17:32] 🔴 SSH brute force
        IP: 45.33.32.156 (CN)
        Attempts: 23
        Users tried: root, admin, ubuntu

[17:28] 🟡 SSH login attempt  
        IP: 185.220.101.34 (DE)
        User: postgres
        Pass: postgres123

[17:15] 🔴 SSH brute force
        IP: 89.248.167.131 (NL)
        Attempts: 156
        Duration: 4m 12s

Showing 3 of 47 today
Full logs: /logs 20
```

**Response (no activity):**
```
📜 No Recent Activity

Your honeypot hasn't captured any attacks yet.
This is normal for new deployments - give it time!

Tip: Honeypots typically see first contact within 15 minutes.
```

---

### `/pricing`

**Purpose:** Show pricing tiers and payment information

**Response:**
```
💰 Honey Claw Pricing

FREE TIER
• 1 honeypot
• 24h log retention
• Basic templates
• $0/month

HUNTER
• 5 honeypots
• 30-day retention
• All templates
• API access
• $29/month (0.0012 BTC)

ENTERPRISE
• Unlimited honeypots
• 1-year retention
• Custom templates
• Priority support
• Contact us

─────────────────────────

Payment: BTC, ETH, USDC accepted

To upgrade, send payment to:
BTC: bc1q...honeyclaw
ETH: 0x...honeyclaw

Include your Telegram ID in memo:
Your ID: {user_id}

Questions? @honeyclaw_support
```

---

### `/help`

**Purpose:** List all available commands

**Response:**
```
🍯 Honey Claw Commands

/start - Welcome & intro
/deploy <template> - Deploy honeypot
/status - Check your honeypots
/logs - View attack logs
/pricing - Plans & payment
/help - This message

Templates: ssh, web, mysql

Need help? @honeyclaw_support
```

---

## Internal Commands (Admin Only)

### `/admin stats`
Show global statistics (total users, deployments, attacks)

### `/admin user <id>`
Look up specific user's account

### `/admin broadcast <message>`
Send message to all users

**Auth:** Check against `ADMIN_USER_IDS` env var

---

## Error Handling

All errors follow this format:
```
❌ Error: {description}

{helpful suggestion or next step}
```

## Rate Limiting

| Command | Limit |
|---------|-------|
| `/deploy` | 3 per hour |
| `/logs` | 10 per minute |
| `/status` | 20 per minute |
| Others | 30 per minute |

Exceeded response:
```
⏳ Slow down! 

You've hit the rate limit for this command.
Try again in {seconds} seconds.
```

## Inline Keyboards (Future)

MVP uses text commands. v2 will add inline keyboards:
- Template selection buttons
- Log pagination
- Quick actions (stop/restart honeypot)
