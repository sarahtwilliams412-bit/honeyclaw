# Container Escape Detection

Honeyclaw includes a comprehensive container escape detection module that monitors for attacker attempts to break out of the honeypot sandbox.

## Overview

When attackers compromise a honeypot, sophisticated adversaries may attempt to escape the container to gain access to the host system. The escape detection module monitors for these attempts in real-time, providing:

- **40+ detection patterns** covering Docker socket access, namespace manipulation, cgroup exploits, capability abuse, and known CVEs
- **Configurable responses**: Alert only (gather intel), kill container, migrate to deeper sandbox, or block command
- **MITRE ATT&CK mapping** for all patterns
- **Integration with Honeyclaw alerting** for real-time notifications

## Quick Start

### Basic Usage

```python
from src.security import check_command

# Check a command for escape patterns
is_escape, detections = check_command(
    "nsenter -t 1 -m -p -- /bin/bash",
    source_ip="192.168.1.100",
    session_id="sess_abc123"
)

if is_escape:
    for d in detections:
        print(f"Escape attempt: {d.pattern_name} (severity: {d.severity})")
```

### Integration with Honeypot Shell Handler

```python
from src.security import get_detector, create_command_hook

# Create detector with desired response
detector = get_detector()
detector.set_response(EscapeResponse.ALERT_ONLY)  # Gather intel

# Create hook for shell commands
command_hook = create_command_hook(detector, block_on_detect=False)

# In your shell command handler:
def handle_command(command, client_ip, session_id):
    # Check for escape attempt
    should_allow, result = command_hook(command, client_ip, session_id)
    
    if not should_allow:
        return f"Permission denied: {result}"
    
    # Continue processing command...
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ESCAPE_RESPONSE` | `alert_only` | Response action: `alert_only`, `kill`, `migrate`, `block` |
| `ESCAPE_MIN_SEVERITY` | `5` | Minimum severity to trigger (1-10) |
| `HONEYPOT_ID` | `honeyclaw` | Identifier for alerts |

### Response Actions

| Action | Behavior | Use Case |
|--------|----------|----------|
| `alert_only` | Log and alert, allow command | Gather threat intel on sophisticated attackers |
| `kill` | Terminate container immediately | Maximum security, prevent escape |
| `migrate` | Move to deeper isolation | Balance intel gathering and security |
| `block` | Block the specific command | Prevent escape while keeping session |

### Programmatic Configuration

```python
from src.security import configure_detector, EscapeResponse

configure_detector(
    response="kill",           # or EscapeResponse.KILL_CONTAINER
    min_severity=7,            # Only trigger on severity 7+
    alert_callback=my_alert,   # Custom alert function
    kill_callback=my_kill,     # Custom kill function
)
```

## Detection Categories

### Docker Socket Access (Severity: 10)
- Direct `/var/run/docker.sock` access
- Docker API calls via curl
- Privileged container spawning
- Host filesystem volume mounts

### Namespace Escape (Severity: 8-10)
- `nsenter` to join host namespaces
- `unshare` with root mapping
- `setns` syscall usage

### Cgroup Exploits (Severity: 8-10)
- `release_agent` manipulation (CVE-2022-0492)
- `notify_on_release` abuse
- Cgroup hierarchy manipulation

### Capability Abuse (Severity: 6-10)
- CAP_SYS_ADMIN exploitation
- CAP_SYS_PTRACE for process injection
- DAC override capabilities

### /proc Manipulation (Severity: 6-9)
- `/proc/*/root` access
- Namespace file access
- File descriptor escape

### Known CVEs (Severity: 9-10)
- CVE-2022-0492: Cgroup release_agent
- CVE-2020-15257: Containerd socket
- CVE-2019-5736: runc escape
- CVE-2022-0847: Dirty Pipe
- CVE-2022-0185: fsconfig heap overflow
- CVE-2021-3490: eBPF verifier bypass

### Mount/Filesystem (Severity: 7-10)
- Host filesystem mounting
- debugfs access
- sysfs manipulation

### Privileged Execution (Severity: 7-10)
- Kernel module loading (insmod/modprobe)
- Device node creation (mknod)
- chroot/pivot_root escape

## Alert Integration

Escape detections automatically integrate with the Honeyclaw alerting system:

```python
# Alerts are sent to configured webhooks with:
{
    "event": "escape_attempt",
    "severity": "CRITICAL",
    "pattern_name": "cve_2022_0492",
    "category": "known_cve",
    "pattern_severity": 10,
    "command": "echo /pwn > /sys/fs/cgroup/.../release_agent",
    "source_ip": "192.168.1.100",
    "mitre_technique": "T1611"
}
```

## MITRE ATT&CK Mapping

| Technique | Description | Patterns |
|-----------|-------------|----------|
| T1611 | Escape to Host | Docker socket, namespace, cgroup, mount escapes |
| T1068 | Exploitation for Privilege Escalation | CVE exploits (kernel) |
| T1548 | Abuse Elevation Control Mechanism | Capability abuse |
| T1055 | Process Injection | CAP_SYS_PTRACE abuse |
| T1547.006 | Boot/Logon Init Scripts: Kernel Modules | insmod/modprobe |

## Testing

### CLI Testing

```bash
# Check a single command
python -m src.security.escape_detector "nsenter -t 1 -m -p /bin/sh"

# Run test suite with common escape commands
python -m src.security.escape_detector --test

# View statistics
python -m src.security.escape_detector --stats
```

### Test Output

```
$ python -m src.security.escape_detector --test
============================================================
Container Escape Detection Test
============================================================

✅ SAFE: ls -la

🚨 ESCAPE: cat /var/run/docker.sock
   Pattern: docker_socket_access (severity: 10)
   Category: docker_socket
   MITRE: T1611

🚨 ESCAPE: nsenter -t 1 -m -p -n -- /bin/bash
   Pattern: nsenter_command (severity: 10)
   Category: namespace_escape
   MITRE: T1611
...
```

## Statistics and Reporting

```python
from src.security import get_detector

detector = get_detector()
stats = detector.get_stats()

print(f"Total checks: {stats['total_checks']}")
print(f"Detections: {stats['detections']}")
print(f"By category: {stats['by_category']}")
print(f"By severity: {stats['by_severity']}")

# Get recent detection history
history = detector.get_history(limit=50)
```

## Best Practices

### For Maximum Security
```python
configure_detector(
    response="kill",
    min_severity=8,
)
```

### For Threat Intelligence Gathering
```python
configure_detector(
    response="alert_only",
    min_severity=5,
)
```

### For Balanced Approach
```python
configure_detector(
    response="migrate",
    min_severity=7,
)
```

## Adding Custom Patterns

```python
from src.security.patterns import EscapePattern, EscapeCategory
import re

custom_pattern = EscapePattern(
    name="custom_escape",
    pattern=re.compile(r'my_custom_pattern', re.IGNORECASE),
    category=EscapeCategory.PRIVILEGED_EXEC,
    severity=8,
    description="Custom escape pattern",
    mitre_technique="T1611",
    references=["internal-doc-123"],
)

detector = EscapeDetector(
    patterns=get_all_patterns() + [custom_pattern]
)
```

## Enterprise Template

The enterprise-sim template includes escape detection by default:

```yaml
security:
  escape_detection:
    enabled: true
    response: alert_only
    min_severity: 5
    hook_shell_commands: true
```

## Troubleshooting

### Detection Not Firing
- Check `min_severity` setting
- Verify pattern matches with `--test` flag
- Review logs for any initialization errors

### Too Many Alerts
- Increase `min_severity` to reduce noise
- Focus on categories most relevant to your deployment

### Container Not Killing
- Verify `kill_callback` or container permissions
- Check if detector has permission to signal PID 1
- Review `response` setting

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) - Overall system architecture
- [COUNCIL-SECURITY.md](COUNCIL-SECURITY.md) - Security design decisions
- [Alert Dispatcher](../src/alerts/dispatcher.py) - Alert system integration
