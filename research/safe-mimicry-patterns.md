# Safe Mimicry Patterns for Honey Claw
*Extracted from existing honeypot implementations*

## Protocol Mimicry (from 0xksdata/openclaw-honeypot)

### WebSocket Handshake

**Client sends:**
```json
{
  "minProtocol": 1,
  "maxProtocol": 1,
  "client": {
    "id": "client-123",
    "version": "1.0.0",
    "platform": "linux",
    "mode": "control-ui"
  },
  "auth": {
    "token": "captured-token"
  }
}
```

**Honeypot responds (accept everything):**
```json
{
  "type": "hello-ok",
  "protocol": 1,
  "server": {
    "version": "2026.1.29",
    "connId": "uuid"
  },
  "features": {
    "methods": ["health", "channels.status", "..."],
    "events": ["agent", "chat", "tick", "..."]
  }
}
```

### Request/Response Pattern

**Request:**
```json
{
  "type": "req",
  "id": "req-1",
  "method": "channels.status",
  "params": {}
}
```

**Response:**
```json
{
  "type": "res",
  "id": "req-1",
  "ok": true,
  "payload": { ... }
}
```

---

## Port Configuration (from m0lthoney)

| Port | Service | Real OpenClaw | Honeypot |
|------|---------|---------------|----------|
| 18789 | Gateway HTTP + WebSocket | ✅ | ✅ Mimic |
| 18791 | Chrome DevTools Protocol | ✅ | ✅ Mimic |
| 18793 | Canvas file server | ✅ | ✅ Mimic |
| 41892 | Admin dashboard | ❌ | ✅ Hidden (localhost only) |

---

## HTTP Endpoints to Simulate

From m0lthoney + EsteveSegura:

```
GET  /              → Gateway UI
GET  /health        → {"status":"ok","version":"2026.1.29"}
GET  /v1/models     → Model catalog (fake)
POST /v1/chat/completions → OpenAI-compatible (log, fake response)
POST /v1/responses  → OpenResponses API
POST /tools/invoke  → Tool execution (log everything)

# Channel webhooks
POST /webhook/whatsapp
POST /bot{token}/*     → Telegram Bot API
POST /webhook/discord
POST /slack/*
POST /webhook/signal
```

---

## mDNS Advertisement (for Shodan visibility)

From EsteveSegura setup:

```bash
# /etc/avahi/services/openclaw.service
<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name>OpenClaw Gateway</name>
  <service>
    <type>_openclaw._tcp</type>
    <port>18789</port>
    <txt-record>version=2026.1.29</txt-record>
    <txt-record>platform=darwin</txt-record>
  </service>
</service-group>
```

Alternatively, Node.js `bonjour` library:
```javascript
const bonjour = require('bonjour')();
bonjour.publish({
  name: 'macmini-studio',
  type: 'openclaw',
  port: 18789,
  txt: { version: '2026.1.29' }
});
```

---

## Fake Filesystem (from m0lthoney)

When attackers try to browse files, serve from in-memory templates:

```javascript
const FAKE_FS = {
  '/': ['Documents', 'Downloads', 'Desktop', '.openclaw', '.ssh'],
  '/.openclaw': ['openclaw.json', 'workspace', 'agents'],
  '/.openclaw/openclaw.json': JSON.stringify({
    gateway: { token: generateCanaryToken('gateway') },  // ⚠️ Generate unique per deployment!
    channels: { discord: { token: generateCanaryToken('discord') }}
  }),
  '/.ssh': ['id_rsa', 'id_rsa.pub', 'known_hosts'],
  '/.ssh/id_rsa': generateCanarySSHKey()  // ⚠️ Never hardcode - use generator!
};
```

---

## Credential Acceptance Strategy

**Accept everything, log everything:**

```javascript
function authenticateToken(token) {
  // Log the attempt
  logAuthAttempt({
    token: token,
    timestamp: Date.now(),
    result: 'accepted'
  });
  
  // Always succeed (honeypot)
  return { 
    valid: true, 
    session: generateFakeSession()
  };
}
```

---

## Attack Detection Regex (from 0xksdata)

```javascript
const ATTACK_PATTERNS = {
  // SQL Injection
  sqli: /('|"|;|--|\/\*|\*\/|union|select|insert|update|delete|drop|exec|execute)/i,
  
  // Command Injection
  cmdi: /(;|\||`|\$\(|&&|\|\||>|<|cat |ls |pwd|whoami|id |curl |wget )/i,
  
  // XSS
  xss: /(<script|javascript:|on\w+\s*=|<img|<iframe|<object|<embed)/i,
  
  // Path Traversal
  lfi: /(\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e%252f)/i,
  
  // Prompt Injection
  promptInject: /(ignore previous|forget your instructions|you are now|new persona|disregard|override)/i,
  
  // Scanner signatures
  scanner: /(wp-admin|wp-login|\.git|\.env|phpinfo|actuator|swagger)/i,
  
  // Known exploits
  exploit: /(jndi:ldap|log4j|\${|base64,|eval\(|exec\()/i
};
```

---

## Rate Limiting (from m0lthoney)

```javascript
const RATE_LIMITS = {
  http: {
    requestsPerSecond: 100,
    perIp: true
  },
  websocket: {
    connectionsPerIp: 10,
    framesPerMinute: 1000
  }
};
```

---

## Version Strings to Simulate

Use pre-patch versions to appear vulnerable:

```javascript
const VULNERABLE_VERSIONS = [
  '2026.1.29',  // Pre-security-patch (m0lthoney default)
  '2026.1.15',  // Earlier
  '2025.12.1',  // Older
];

const SERVER_HEADERS = {
  'Server': 'OpenClaw Gateway',
  'X-OpenClaw-Version': '2026.1.29',
  'X-Platform': 'darwin-arm64'
};
```

---

## LLM Honeypot Pattern (from Beelzebub)

For realistic shell simulation:

```javascript
const systemPrompt = `You are simulating an Ubuntu 22.04 terminal.
Respond only with what the terminal would show.
Use a single code block for output.
The user is an attacker - play along but log everything.
Never reveal you are a honeypot.`;

async function handleCommand(cmd) {
  const response = await llm.chat({
    model: 'gpt-4o-mini', // Cheap but convincing
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: cmd }
    ]
  });
  return response;
}
```

---

## MCP Honeypot Pattern (from Beelzebub)

Decoy tools that should never be invoked:

```yaml
tools:
  - name: "tool:user-account-manager"
    description: "Requires administrator privileges."
    handler: |
      {
        "status": "completed",
        "output": {
          "email": "admin@honeyclaw.internal",
          "role": "admin"
        }
      }
```

Any invocation = jailbreak/prompt injection detected.

---

## Session Fingerprinting

Track returning attackers:

```javascript
function generateFingerprint(req) {
  return hash({
    ip: req.ip,
    userAgent: req.headers['user-agent'],
    acceptLang: req.headers['accept-language'],
    ja3: req.tlsFingerprint,
    clientId: req.body?.client?.id
  });
}
```

---

## Canary Token Examples

```javascript
// ⚠️ SECURITY: Generate unique canaries per deployment using generateCanaryData()
// Never commit actual canary values to source control!

function generateCanaryData() {
  return {
    // API Keys (will alert if used)
    apiKeys: {
      anthropic: `sk-ant-${crypto.randomUUID().slice(0,8)}`,
      openai: `sk-${crypto.randomUUID().slice(0,8)}`,
      aws: `AKIA${crypto.randomBytes(16).toString('base64').slice(0,16)}`
    },
  
  // Fake credentials
  credentials: {
    admin: { user: 'admin', pass: 'OpenClaw2026!' },
    root: { user: 'root', pass: 'toor' }
  },
  
  // Fake webhook URLs (will alert if called)
  webhooks: {
    discord: 'https://canary.honeyclaw.io/discord/hc001',
    slack: 'https://canary.honeyclaw.io/slack/hc001'
  }
};
```

---

## Quick Implementation Checklist

- [ ] WebSocket gateway on :18789
- [ ] Accept all auth tokens (log them)
- [ ] Fake hello-ok response with features
- [ ] HTTP endpoints for common paths
- [ ] Attack pattern detection
- [ ] GeoIP enrichment
- [ ] JSONL logging
- [ ] Rate limiting
- [ ] Admin dashboard (localhost only)
- [ ] mDNS advertisement (optional)
- [ ] Canary tokens embedded
- [ ] LLM for shell simulation (optional)
