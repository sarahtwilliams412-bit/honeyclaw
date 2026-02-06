# Architecture Council Verdict
*Analyst: Architecture Expert*
*Date: 2026-02-05*

---

## Architecture Assessment

### Current State: 🟡 ADEQUATE FOR MVP

The architecture is well-designed conceptually but has implementation gaps that will cause scaling and maintenance issues.

---

## Top 5 Architecture Issues

### 1. No Centralized Configuration Management
**Severity:** HIGH
**Impact:** Maintenance nightmare as templates grow

**Current State:**
- Each template has its own `config.yaml`
- Environment variables scattered across files
- No validation of configuration at startup

**Recommended Architecture:**
```
honeyclaw/
├── config/
│   ├── schema.json          # JSON Schema for validation
│   ├── defaults.yaml        # Default values
│   └── environments/
│       ├── development.yaml
│       ├── staging.yaml
│       └── production.yaml
├── src/
│   └── config/
│       ├── loader.py        # Config loading with validation
│       └── types.py         # Type definitions
```

**Implementation:**
```python
# src/config/loader.py
from pydantic import BaseSettings, validator

class HoneypotConfig(BaseSettings):
    port: int = 8022
    log_path: str = "/var/log/honeypot"
    log_format: str = "json"
    rate_limit_per_minute: int = 60
    host_key_path: str = "/data/ssh_host_key"
    
    @validator('port')
    def port_valid(cls, v):
        if not 1 <= v <= 65535:
            raise ValueError('port must be 1-65535')
        return v
    
    class Config:
        env_prefix = 'HONEYCLAW_'
```

**Effort:** 4 hours

---

### 2. Missing Health Check Infrastructure
**Severity:** HIGH
**Impact:** Silent failures, poor observability

**Current State:**
- No /health endpoints
- Fly.io only checks port availability
- No readiness vs liveness distinction

**Recommended Implementation:**
```python
# src/health.py
from aiohttp import web
import asyncio

class HealthChecker:
    def __init__(self, honeypot):
        self.honeypot = honeypot
        self.start_time = time.time()
    
    async def health(self, request):
        return web.json_response({
            'status': 'healthy',
            'uptime_seconds': time.time() - self.start_time,
            'connections_total': self.honeypot.connection_count,
            'version': '0.1.0'
        })
    
    async def ready(self, request):
        # Check all dependencies
        checks = {
            'log_writable': self._check_log_writable(),
            'host_key_loaded': self._check_host_key()
        }
        all_ready = all(checks.values())
        status = 200 if all_ready else 503
        return web.json_response(checks, status=status)
```

**Fly.toml Addition:**
```toml
[[services.http_checks]]
  interval = 10000
  grace_period = "5s"
  method = "get"
  path = "/health"
  protocol = "http"
  timeout = 2000
```

**Effort:** 3 hours

---

### 3. No Graceful Shutdown
**Severity:** MEDIUM
**Impact:** Lost log data, incomplete attack records

**Current State:**
```python
# honeypot.py - No signal handling
while True:
    await asyncio.sleep(3600)
```

**Recommended Implementation:**
```python
import signal

class GracefulShutdown:
    def __init__(self):
        self.shutdown_event = asyncio.Event()
        
    def handle_signal(self, sig):
        log_event('shutdown', {'signal': sig.name})
        self.shutdown_event.set()

async def start_server():
    shutdown = GracefulShutdown()
    loop = asyncio.get_event_loop()
    
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, shutdown.handle_signal, sig)
    
    server = await create_server()
    
    await shutdown.shutdown_event.wait()
    
    # Graceful shutdown
    log_event('draining', {'active_connections': server.active_count})
    server.close()
    await server.wait_closed()
    await flush_logs()
```

**Effort:** 2 hours

---

### 4. Shared Logging Module Missing
**Severity:** MEDIUM
**Impact:** Code duplication, inconsistent log format

**Current State:**
- Each service has its own `log_event()` function
- Log format varies between services
- No shared schema enforcement

**Recommended Architecture:**
```
honeyclaw/
├── src/
│   └── logging/
│       ├── __init__.py
│       ├── schema.py      # Pydantic models for events
│       ├── formatter.py   # JSON formatting
│       ├── shipper.py     # S3/stdout shipping
│       └── buffer.py      # In-memory buffer for batching
```

**Implementation:**
```python
# src/logging/schema.py
from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Dict, Any

class LogEvent(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    honeypot_id: str
    service: str
    event_type: str
    source_ip: Optional[str]
    source_port: Optional[int]
    payload: Dict[str, Any] = {}
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + 'Z'
        }

# src/logging/__init__.py
from .schema import LogEvent
from .shipper import LogShipper

_shipper = None

def init(honeypot_id: str, service: str):
    global _shipper
    _shipper = LogShipper(honeypot_id, service)

def log(event_type: str, **kwargs):
    event = LogEvent(event_type=event_type, **kwargs)
    _shipper.ship(event)
```

**Effort:** 4 hours

---

### 5. No Service Discovery/Registry
**Severity:** LOW (for MVP)
**Impact:** Hard to manage at scale

**Current State:**
- Templates are independent
- No way to list running honeypots
- Manual tracking required

**Future Architecture (Post-MVP):**
```yaml
# docker-compose.yaml for local development
services:
  registry:
    image: consul:latest
    
  ssh-honeypot:
    build: ./templates/basic-ssh
    environment:
      - CONSUL_HTTP_ADDR=registry:8500
      - SERVICE_NAME=honeyclaw-ssh
```

**Effort:** Not needed for MVP, 1 day for future

---

## Recommended Project Structure

```
honeyclaw/
├── src/
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py         # Centralized config
│   │   ├── logging.py        # Shared logging
│   │   ├── health.py         # Health checks
│   │   └── lifecycle.py      # Startup/shutdown
│   ├── services/
│   │   ├── ssh/
│   │   ├── rdp/
│   │   ├── api/
│   │   └── enterprise/
│   └── cli/
│       └── __init__.py       # CLI entrypoint
├── templates/                 # Docker templates only
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── config/
├── docs/
└── pyproject.toml
```

---

## Effort Summary

| Task | Priority | Hours | Assignee |
|------|----------|-------|----------|
| Centralized config | P1 | 4h | hitteam-2 |
| Health check endpoints | P1 | 3h | hitteam-2 |
| Graceful shutdown | P1 | 2h | hitteam-2 |
| Shared logging module | P2 | 4h | hitteam-2 |
| Project restructure | P2 | 4h | hitteam-2 |
| **Total** | | **17h** | |

---

## VERDICT: 🟡 PROCEED WITH CAUTION

The architecture is sound for MVP but needs the P1 fixes before scaling. The current structure will become a liability as templates multiply.

*Signed: Architecture Council*
