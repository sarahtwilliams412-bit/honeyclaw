# Implement Log Rotation (High)

**Priority:** High
**Effort:** Small
**Depends on:** Nothing

## Problem

The honeypot appends to `LOG_PATH` (default `/data/logs/ssh.json`) indefinitely. On a persistent volume, this will eventually exhaust disk space and cause the honeypot to fail.

## Proposed Solution

Add size-based log rotation to `honeypot.py`. When the log file exceeds a configurable size (default 100MB), rotate it:

1. Rename `ssh.json` to `ssh.json.1`
2. Rename `ssh.json.1` to `ssh.json.2` (up to N backups)
3. Delete the oldest backup
4. Create a fresh `ssh.json`

### Option A: Python `RotatingFileHandler`

Replace the manual file append in `log_event()` with Python's `logging.handlers.RotatingFileHandler`:

```python
import logging.handlers

log_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=100_000_000, backupCount=5
)
```

This gives you 100MB x 5 = 500MB max disk usage for logs.

### Option B: Size Check in `log_event()`

Add a simple check at the top of `log_event()`:

```python
MAX_LOG_SIZE = int(os.environ.get("MAX_LOG_SIZE_MB", "100")) * 1024 * 1024

def log_event(event_type, data):
    # Rotate if needed
    if LOG_FILE.exists() and LOG_FILE.stat().st_size > MAX_LOG_SIZE:
        rotate_logs()
    # ... rest of function
```

### Environment Variables

- `MAX_LOG_SIZE_MB` -- Maximum log file size before rotation (default: 100)
- `MAX_LOG_BACKUPS` -- Number of rotated files to keep (default: 5)

## Files to Modify

- `templates/basic-ssh/honeypot.py` -- Add rotation logic to `log_event()`

## Success Criteria

- Log file never exceeds `MAX_LOG_SIZE_MB`
- Rotated files are numbered (`ssh.json.1`, `ssh.json.2`, etc.)
- Oldest backup is deleted when limit is reached
- No log entries are lost during rotation
- Total disk usage stays under `MAX_LOG_SIZE_MB * (MAX_LOG_BACKUPS + 1)`
