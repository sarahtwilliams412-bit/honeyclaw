# Anti-Fingerprinting Improvements (Medium)

**Priority:** Medium
**Effort:** Large
**Depends on:** 01-fix-ssh-handshake.md, 03-openssh-algorithm-ordering.md
**See also:** docs/IMPROVEMENT-PLAN.md Section 3.1

## Problem

The security audit identified multiple ways attackers can detect the honeypot in under 5 seconds:

1. **No SSH banner sent** (fixed by SSH handshake fix)
2. **Algorithm ordering mismatch** (separate task: 03)
3. **Response timing is too uniform** -- real servers have natural jitter
4. **OS/TCP fingerprint reveals container** -- `nmap -O` shows Docker/Fly.io, not Ubuntu
5. **Shodan/Censys databases** -- IP may already be flagged as honeypot
6. **PTR record** -- generic cloud rDNS is suspicious
7. **Error messages differ** -- asyncssh error strings don't match OpenSSH

## Tasks

### 4a. Response Timing Jitter (Small)

Add Gaussian-distributed random delays to responses to match natural server behavior:

```python
import random

async def jittered_response(base_delay_ms=50, stddev_ms=15):
    delay = max(0, random.gauss(base_delay_ms / 1000, stddev_ms / 1000))
    await asyncio.sleep(delay)
```

Apply to `begin_auth`, `validate_password`, and `validate_public_key`.

### 4b. Shodan/Censys Check (Small)

Before deploying, query the IP against honeypot databases:

```bash
# Check Shodan
curl -s "https://api.shodan.io/shodan/host/149.248.202.23?key=$SHODAN_API_KEY" | jq '.tags'

# Check GreyNoise
curl -s "https://api.greynoise.io/v3/community/149.248.202.23" | jq '.classification'
```

Create a pre-deploy script `scripts/check-ip-reputation.sh` that fails if the IP is flagged.

### 4c. Error Message Matching (Medium)

Compare asyncssh error responses byte-for-byte against OpenSSH 8.9p1:

| Scenario | OpenSSH Response | asyncssh Response | Match? |
|----------|-----------------|-------------------|--------|
| Wrong password | `Permission denied (publickey,password).` | ? | Check |
| Too many auth failures | `Too many authentication failures` | ? | Check |
| Invalid username chars | ? | ? | Check |

Override asyncssh error messages where they diverge.

### 4d. TCP Stack Fingerprinting (Hard)

`nmap -O` can distinguish containerized from bare-metal systems via TCP window size, TTL, and IP ID behavior. This is difficult to fix from userspace and may require kernel parameter tuning on the Fly.io VM.

Document as an accepted limitation, or investigate:
- Fly.io kernel parameter access
- TCP window size tuning via sysctl

## Files to Modify

- `templates/basic-ssh/honeypot.py` -- Timing jitter
- New: `scripts/check-ip-reputation.sh` -- Pre-deploy IP check
- New: `tests/anti_fingerprint/` -- Fingerprinting test suite

## Success Criteria

- Response timing has visible jitter in pcap analysis
- IP reputation check runs before every deploy
- Error messages match OpenSSH for common scenarios
- `nmap -sV -p 8022 host` reports OpenSSH (not asyncssh)

## References

- `test-results/evasion.md` -- Current detection results
- `reviews/expert-1-offensive.md` -- TCP fingerprinting concerns
- `reviews/expert-4-deception.md` -- Shodan, host key stability, OS fingerprint
- `docs/IMPROVEMENT-PLAN.md` Section 3.1 -- Full anti-fingerprinting spec
