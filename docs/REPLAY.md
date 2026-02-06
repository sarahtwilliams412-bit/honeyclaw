# 📹 Session Replay System

Record and replay attacker sessions like a movie. Watch SSH terminal sessions with full timing, see what attackers typed and what they saw.

## Features

- **SSH Terminal Recording** — Full asciinema-compatible recordings with timing
- **HTTP Request Logging** — HAR format for HTTP request/response chains
- **Web Dashboard** — Built-in player using asciinema-player.js
- **CLI Tools** — List, play, share, and export recordings
- **Storage Backends** — Local filesystem or S3-compatible storage
- **Shareable Links** — Token-based sharing for collaboration

## Quick Start

### Recording Sessions

Use the integration helpers to add recording to your honeypot:

```python
from src.replay.integration import RecordingSSHSession

# Create a recording session
session = RecordingSSHSession(
    source_ip=client_ip,
    source_port=client_port,
    dest_port=22,
    username=username
)

# Record what the honeypot sends
session.record_output("Welcome to Ubuntu 20.04\n")
session.record_output("$ ")

# Record what the attacker types  
session.record_input("whoami\n")

# Save when connection closes
path = session.save()
print(f"Saved: {path}")
```

### CLI Commands

```bash
# List all recordings
honeyclaw replay list

# Filter by protocol or IP
honeyclaw replay list --protocol ssh --ip 45.33.32.156

# Play in console (real-time)
honeyclaw replay show abc123

# Play at 2x speed
honeyclaw replay show abc123 --speed 2.0

# Open web-based player
honeyclaw replay show abc123 --web

# Export to file
honeyclaw replay show abc123 --export session.cast

# Show recording details
honeyclaw replay info abc123

# Create share link
honeyclaw replay share abc123

# Delete recording
honeyclaw replay delete abc123
```

## Architecture

```
src/replay/
├── __init__.py          # Public API exports
├── recorder.py          # SSHRecorder, HTTPRecorder - recording logic
├── player.py            # SessionPlayer - playback with seeking/speed
├── storage.py           # LocalStorage, S3Storage - persistence
├── integration.py       # Helpers for honeypot integration
└── tests/               # Comprehensive test suite

dashboard/replay/
├── index.html           # Web player UI
├── player.js            # JavaScript controller
└── style.css            # Dark theme styling
```

## Recording Formats

### SSH (asciinema v2)

SSH sessions are recorded in asciinema v2 format (NDJSON):

```json
{"version": 2, "width": 80, "height": 24, "timestamp": 1707235200, "honeyclaw": {...}}
[0.0, "o", "Welcome to server\n"]
[0.5, "o", "$ "]
[1.2, "i", "ls\n"]
[1.3, "o", "file.txt\n$ "]
```

Event types:
- `o` — Output (what attacker sees)
- `i` — Input (what attacker types)

### HTTP (HAR 1.2)

HTTP sessions use HAR format with Honeyclaw metadata:

```json
{
  "log": {
    "version": "1.2",
    "creator": {"name": "Honeyclaw", "version": "1.0.0"},
    "entries": [
      {
        "startedDateTime": "2026-02-06T12:00:00Z",
        "request": {...},
        "response": {...}
      }
    ],
    "_honeyclaw": {
      "session_id": "abc123",
      "source_ip": "1.2.3.4"
    }
  }
}
```

## Storage Configuration

### Local Storage (Default)

```bash
# Set recordings path
export HONEYCLAW_RECORDINGS_PATH=/var/lib/honeyclaw/recordings
```

Directory structure:
```
/var/lib/honeyclaw/recordings/
├── index.json           # Session metadata index
├── tokens.json          # Share token mappings
└── 2026/02/06/
    ├── abc123.cast      # SSH recording
    └── def456.har       # HTTP recording
```

### S3 Storage

```bash
export HONEYCLAW_STORAGE=s3
export HONEYCLAW_S3_BUCKET=my-honeyclaw-bucket
export HONEYCLAW_S3_PREFIX=recordings/
export AWS_REGION=us-east-1

# Optional: Custom endpoint (MinIO, Wasabi, etc.)
export HONEYCLAW_S3_ENDPOINT=https://s3.example.com
```

## Web Player

The web player at `dashboard/replay/` provides:

- **Terminal Display** — Full terminal emulation via asciinema-player
- **Playback Controls** — Play, pause, restart, speed control (0.25x-4x)
- **Timeline** — Visual progress with event markers
- **Event List** — Scrollable list of all events
- **Session Info** — IP, username, timing, event count
- **Export** — Download as `.cast` or `.txt`

### Launching the Player

```bash
# Start web player on port 8765
honeyclaw replay show abc123 --web

# Use custom port
honeyclaw replay show abc123 --web --port 9000
```

## API Endpoints

When the web player is running, these endpoints are available:

- `GET /api/recording` — Full recording data as JSON
- `GET /api/info` — Session metadata
- `GET /api/cast` — Raw asciinema format (NDJSON)

## Integration Examples

### With Basic SSH Honeypot

```python
import asyncssh
from src.replay.integration import RecordingSSHSession

class RecordingServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        peername = conn.get_extra_info('peername')
        self.recording = RecordingSSHSession(
            source_ip=peername[0],
            source_port=peername[1],
            dest_port=22
        )
    
    def connection_lost(self, exc):
        self.recording.save()
```

### With AI Deception Module

```python
from src.ai.engine import HoneypotAI
from src.replay.integration import RecordingSSHSession

async def handle_session(conn):
    recording = RecordingSSHSession(...)
    ai = HoneypotAI()
    
    async for command in conn.stdin:
        recording.record_input(command)
        response = await ai.respond(command)
        recording.record_output(response)
        conn.stdout.write(response)
```

## Best Practices

1. **Storage Rotation** — Set up log rotation for old recordings
2. **Sensitive Data** — Be aware recordings may contain attacker payloads
3. **Disk Space** — Monitor disk usage; long sessions can grow large
4. **Sharing** — Use share tokens for external collaboration
5. **Retention** — Define a retention policy for compliance

## Troubleshooting

### "No recordings found"

Check the recordings path:
```bash
echo $HONEYCLAW_RECORDINGS_PATH
ls -la ${HONEYCLAW_RECORDINGS_PATH:-/var/lib/honeyclaw/recordings}
```

### Web player not loading

Verify the recording exists and has events:
```bash
honeyclaw replay info <session_id>
```

### S3 access issues

Test S3 credentials:
```bash
aws s3 ls s3://${HONEYCLAW_S3_BUCKET}/${HONEYCLAW_S3_PREFIX}
```

---

*Part of the Honeyclaw honeypot framework*
