# Functional Test Results

**Test Executor:** Subagent (exec-functional)  
**Target:** 149.248.202.23:8022  
**Date:** 2026-02-07 09:28-09:35 PST  
**Expert Reviews:** 4/4 present before testing began

## Summary

| Test | Result | Notes |
|------|--------|-------|
| F-01 | **FAIL** | Connection reset after SSH version exchange |
| F-02 | **FAIL** | Cannot reach password prompt |
| F-03 | **PARTIAL** | TCP connects, no SSH banner received |
| F-04 | **FAIL** | All 5 credential attempts reset |
| F-05 | **FAIL** | Connection died after ~5 seconds |

**Overall: 0/5 PASS, 1/5 PARTIAL, 4/5 FAIL**

---

## Detailed Results

### F-01: Basic SSH Connection

**Command:** `ssh -p 8022 -o ConnectTimeout=10 test@149.248.202.23`

**Output:**
```
debug1: Connecting to 149.248.202.23 [149.248.202.23] port 8022.
debug1: Connection established.
debug1: Local version string SSH-2.0-OpenSSH_10.0
kex_exchange_identification: read: Connection reset by peer
Connection reset by 149.248.202.23 port 8022
```

**Result:** FAIL

**Notes:**  
- TCP handshake completes successfully
- Connection is reset immediately after client sends SSH version string
- Server never sends its version banner
- This occurs 100% of the time across multiple attempts

---

### F-02: Auth Capture

**Command:** `expect` script attempting login with admin/admin123

**Output:**
```
spawn ssh -p 8022 admin@149.248.202.23
kex_exchange_identification: read: Connection reset by peer
Connection reset by 149.248.202.23 port 8022
CONNECTION_RESET
```

**Result:** FAIL

**Notes:**  
- Never reaches password prompt
- Connection reset during key exchange phase
- Cannot test credential capture functionality
- Auth logging cannot be verified

---

### F-03: Banner Check

**Command:** `nc -v 149.248.202.23 8022`

**Output:**
```
Connection to 149.248.202.23 port 8022 [tcp/oa-system] succeeded!
```

**Python socket test:**
```python
# Connected successfully
# No server banner received (empty bytes)
# Sent: SSH-2.0-OpenSSH_8.9
# Result: ConnectionResetError [Errno 54] Connection reset by peer
```

**Result:** PARTIAL

**Notes:**  
- TCP port 8022 is open and accepting connections
- No SSH banner is sent by the server
- Server waits for client version, then resets connection
- Standard SSH servers send their banner first (RFC 4253)

---

### F-04: Multiple Auth Attempts

**Command:** SSH connections with 5 different usernames

**Output:**
```
=== Testing admin@149.248.202.23:8022 ===
kex_exchange_identification: read: Connection reset by peer

=== Testing root@149.248.202.23:8022 ===
kex_exchange_identification: read: Connection reset by peer

=== Testing user@149.248.202.23:8022 ===
kex_exchange_identification: read: Connection reset by peer

=== Testing test@149.248.202.23:8022 ===
kex_exchange_identification: read: Connection reset by peer

=== Testing guest@149.248.202.23:8022 ===
kex_exchange_identification: read: Connection reset by peer
```

**Result:** FAIL

**Notes:**  
- All 5 credential pairs failed identically
- Connection reset occurs before authentication phase
- Cannot verify rate limiting or credential logging
- Issue is consistent regardless of username

---

### F-05: Connection Persistence

**Command:** Hold nc connection for 60 seconds

**Output:**
```
Testing connection persistence (60 seconds)...
Connection died at 5s
```

**Result:** FAIL

**Notes:**  
- TCP connection established successfully
- Connection terminated after approximately 5 seconds
- Cannot sustain connection for 60 seconds as required
- May indicate idle timeout or connection cleanup issue

---

## Issues Found

### CRITICAL: SSH Honeypot Not Functioning

1. **No SSH Banner Sent**
   - The honeypot does not send an SSH server identification string
   - Per RFC 4253, server should send `SSH-2.0-...` banner upon connection
   - Client is forced to send first, which is protocol-incorrect

2. **Connection Reset on Version Exchange**
   - After receiving client version string, server immediately resets connection
   - Suggests issue with SSH protocol handler or key exchange initialization
   - Possible causes:
     - Missing or invalid host keys
     - asyncssh configuration error
     - Exception during connection handling

3. **Short Connection Lifespan (~5s)**
   - Even raw TCP connections are terminated within 5 seconds
   - May indicate aggressive connection timeout or cleanup

### Recommendations

1. **Immediate:** Check HoneyClaw service logs for errors
2. **Verify:** Host key generation and permissions
3. **Check:** asyncssh configuration and event handlers
4. **Test:** Local connection from honeypot host (loopback)
5. **Review:** Rate limiting configuration (may be too aggressive)

### Environment Notes

- Target confirmed reachable via TCP (nc succeeds)
- No firewall issues (port 8022 responds)
- OpenSSH 10.0 client used for testing
- Multiple retry attempts all show identical behavior
- Tests run from macOS client (Darwin 25.2.0 arm64)

---

## Conclusion

The HoneyClaw SSH honeypot at 149.248.202.23:8022 is **not functioning as an SSH service**. While the TCP port is open and accepting connections, the SSH protocol handler appears to be broken or misconfigured. The honeypot cannot:

- Complete SSH handshake
- Accept authentication attempts
- Capture credentials
- Maintain persistent sessions

**Recommendation:** Debug honeypot deployment before proceeding with further testing. Review service logs and asyncssh configuration.
