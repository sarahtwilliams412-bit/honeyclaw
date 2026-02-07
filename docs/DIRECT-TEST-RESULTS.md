# HoneyClaw Direct Test Results

**Test Date:** 2026-02-07 12:39 PST  
**Target:** 149.248.202.23:8022  
**Tester:** Main Agent (direct testing due to fleet Discord issues)

---

## Executive Summary

**CRITICAL: The honeypot SSH service is non-functional.** It accepts connections but immediately resets them without completing the SSH protocol handshake. This is either a severe bug or misconfiguration.

### Key Findings
1. ❌ **No SSH banner returned** - Server never sends version string
2. ❌ **Connection reset after ~3 seconds** - Always RST after client version
3. ⚠️ **Easily fingerprinted as Fly.io** - Hostname reveals hosting provider
4. ❌ **Service appears broken** - Cannot trap any attackers in current state

---

## Test 1: Connection Behavior

### Command
```bash
ssh -v root@149.248.202.23 -p 8022 2>&1 | head -50
```

### Output
```
debug1: OpenSSH_10.0p2, LibreSSL 3.3.6
debug1: Reading configuration data /Users/sarah/.ssh/config
debug1: Connecting to 149.248.202.23 [149.248.202.23] port 8022.
debug1: Connection established.
debug1: identity file /Users/sarah/.ssh/id_rsa type -1
[... identity file checks ...]
debug1: Local version string SSH-2.0-OpenSSH_10.0
kex_exchange_identification: read: Connection reset by peer
Connection reset by 149.248.202.23 port 8022
```

### Analysis
- **TCP connection succeeds** - Port is open and accepting
- **Server never sends banner** - No `SSH-2.0-*` version string received
- **Connection reset after client sends version** - RST sent ~3 seconds after client version string
- **No key exchange occurs** - Protocol fails at version identification stage

### Banner/Version String
**None.** The server does not send an SSH version banner before or after the client sends its version.

---

## Test 2: Fingerprinting Analysis

### IP Information
```bash
curl -s "https://ipinfo.io/149.248.202.23"
```

**Result:**
```json
{
  "ip": "149.248.202.23",
  "hostname": "ip-149-248-202-23.customer.flyio.net",
  "city": "Pitkin",
  "region": "Colorado",
  "country": "US",
  "org": "AS40509 Fly.io, Inc.",
  "anycast": true
}
```

### Port Scan
```bash
nmap -p 22,80,443,2222,8022,8080,8443 149.248.202.23
```

**Result:**
```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
2222/tcp open  EtherNetIP-1
8080/tcp open  http-proxy
8443/tcp open  https-alt
```

### Version Detection
Nmap version detection (`-sV`) timed out/stalled on port 8022 because the server never returns a banner. This is atypical SSH behavior.

### Fingerprinting Vulnerabilities

| Fingerprint Vector | Status | Details |
|--------------------|--------|---------|
| Reverse DNS | **EXPOSED** | `ip-149-248-202-23.customer.flyio.net` |
| AS Number | **EXPOSED** | AS40509 Fly.io, Inc. |
| Anycast | Disclosed | `anycast: true` |
| SSH Banner | None | No version string (broken?) |
| TCP Behavior | Unusual | Accepts then RSTs - detectable |

**Verdict:** Trivially identifiable as Fly.io infrastructure via reverse DNS and WHOIS. Any attacker can fingerprint this in seconds.

---

## Test 3: Timing Analysis

### Connection Timing (Rapid Sequential)
```python
# 10 rapid TCP connections
for i in range(10):
    connect() → close()
```

**Results:**
```
Conn 0: 0.005s - OK
Conn 1: 0.004s - OK
Conn 2: 0.005s - OK
Conn 3: 0.004s - OK
Conn 4: 0.005s - OK
Conn 5: 0.005s - OK
Conn 6: 0.005s - OK
Conn 7: 0.004s - OK
Conn 8: 0.004s - OK
Conn 9: 0.005s - OK
```

**Finding:** No rate limiting detected. Attackers can scan rapidly.

### Banner Wait Timing
```python
# Connect without sending anything, wait for server banner
connect() → recv() with 30s timeout
```

**Results:**
```
Connected, waiting for server banner...
Received after 3.44s: b''  # Empty data = connection closed
```

**Finding:** Server closes connection after ~3.4 seconds of inactivity with empty response.

### Post-Version Timing
```python
# Send client version, wait for server response
connect() → send('SSH-2.0-OpenSSH_8.9\r\n') → recv()
```

**Results:**
```
Sending SSH version string...
Waiting for response...
Error after 3.10s: [Errno 54] Connection reset by peer
```

**Finding:** Connection RST ~3 seconds after client sends version. Highly consistent.

### Probe Response Testing
| Probe Type | Response |
|------------|----------|
| Empty (wait) | Timeout, then empty close after ~3.4s |
| SSH-2.0-OpenSSH_9.0 | RST after ~3s |
| SSH-1.99-dropbear | RST after ~3s |
| HTTP request | Timeout (no response) |
| Just CRLF | Timeout (no response) |

**All probes fail.** The service does not respond as a valid SSH server.

---

## Additional Findings

### Port 22 vs Port 8022
Both ports exhibit identical behavior:
- TCP accept
- Wait for client version
- RST after ~3 seconds

```bash
ssh -v root@149.248.202.23 -p 22 2>&1 | grep -E "(established|reset)"
# Output:
# debug1: Connection established.
# kex_exchange_identification: read: Connection reset by peer
```

### HTTP Ports (80, 443, 8080, 8443)
- HTTP ports are open but returned no content during testing
- Possible web interface or internal services

---

## Vulnerabilities Discovered

### Critical

1. **SSH Service Non-Functional (CRITICAL)**
   - The honeypot cannot capture any credentials or session data
   - Connection resets before any authentication can occur
   - Root cause: Unknown - possibly misconfigured SSH service or code bug

2. **IP Fingerprinting (HIGH)**
   - Reverse DNS: `ip-149-248-202-23.customer.flyio.net`
   - AS: Fly.io, Inc.
   - Attackers can identify infrastructure provider in one DNS lookup

### High

3. **Missing SSH Banner (HIGH)**
   - Real SSH servers immediately send version string
   - Absence of banner is itself a fingerprint
   - Many scanners will flag this as unusual

4. **Timing Fingerprint (MEDIUM-HIGH)**
   - Consistent ~3-second timeout is unusual
   - Could be used to identify HoneyClaw instances
   - Real SSH servers don't exhibit this behavior

### Medium

5. **No Rate Limiting (MEDIUM)**
   - 10 connections in <0.1s accepted
   - Vulnerable to connection flooding
   - Allows rapid scanning/probing

6. **Multiple Open Ports (MEDIUM)**
   - Ports 22, 80, 443, 2222, 8022, 8080, 8443 all open
   - Larger attack surface
   - May reveal additional information

---

## Recommendations

### Immediate (Before Any Public Deployment)

1. **Fix the SSH Service**
   - The honeypot must complete SSH handshake
   - Should send banner: `SSH-2.0-OpenSSH_X.X HoneyClaw/1.0` (or realistic mimicry)
   - Must accept password attempts to capture credentials

2. **Test SSH Protocol Compliance**
   ```bash
   # Service should pass this basic test
   echo -e 'SSH-2.0-test\r\n' | nc host 8022
   # Should receive: SSH-2.0-<server-version>
   ```

### Short-Term

3. **Use Clean IPs or Proxy**
   - Route through residential/VPS IPs without obvious cloud provider DNS
   - Or accept fingerprinting risk and focus on opportunistic captures

4. **Randomize Timing**
   - Add jitter to timeout values (2-5 seconds random)
   - Prevents timing-based fingerprinting

5. **Implement Rate Limiting**
   - Max 3-5 connections per IP per minute
   - Helps prevent scanning abuse

### Long-Term

6. **Behavioral Honeypot Features**
   - Fake successful logins for common creds
   - Simulate filesystem, capture commands
   - Log everything for threat intelligence

7. **Monitoring & Alerting**
   - Alert on connection volume spikes
   - Log all connection attempts with metadata
   - Track unique IPs and geolocations

---

## Raw Test Outputs

### SSH Verbose Connection Log
```
debug1: OpenSSH_10.0p2, LibreSSL 3.3.6
debug1: Reading configuration data /Users/sarah/.ssh/config
debug1: Reading configuration data /Users/sarah/.colima/ssh_config
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: Reading configuration data /etc/ssh/ssh_config.d/100-macos.conf
debug1: /etc/ssh/ssh_config.d/100-macos.conf line 1: Applying options for *
debug1: Reading configuration data /etc/ssh/crypto.conf
Pseudo-terminal will not be allocated because stdin is not a terminal.
debug1: Authenticator provider $SSH_SK_PROVIDER did not resolve; disabling
debug1: Connecting to 149.248.202.23 [149.248.202.23] port 8022.
debug1: Connection established.
debug1: identity file /Users/sarah/.ssh/id_rsa type -1
debug1: identity file /Users/sarah/.ssh/id_rsa-cert type -1
debug1: identity file /Users/sarah/.ssh/id_ecdsa type -1
debug1: identity file /Users/sarah/.ssh/id_ecdsa-cert type -1
debug1: identity file /Users/sarah/.ssh/id_ecdsa_sk type -1
debug1: identity file /Users/sarah/.ssh/id_ecdsa_sk-cert type -1
debug1: identity file /Users/sarah/.ssh/id_ed25519 type -1
debug1: identity file /Users/sarah/.ssh/id_ed25519-cert type -1
debug1: identity file /Users/sarah/.ssh/id_ed25519_sk type -1
debug1: identity file /Users/sarah/.ssh/id_ed25519_sk-cert type -1
debug1: identity file /Users/sarah/.ssh/id_xmss type -1
debug1: identity file /Users/sarah/.ssh/id_xmss-cert type -1
debug1: Local version string SSH-2.0-OpenSSH_10.0
kex_exchange_identification: read: Connection reset by peer
Connection reset by 149.248.202.23 port 8022
```

### Nmap Port Scan
```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-07 12:42 -0800
Nmap scan report for ip-149-248-202-23.customer.flyio.net (149.248.202.23)
Host is up (0.0045s latency).

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
2222/tcp open  EtherNetIP-1
8080/tcp open  http-proxy
8443/tcp open  https-alt

Nmap done: 1 IP address (1 host up) scanned in 0.04 seconds
```

### IP Info
```json
{
  "ip": "149.248.202.23",
  "hostname": "ip-149-248-202-23.customer.flyio.net",
  "city": "Pitkin",
  "region": "Colorado",
  "country": "US",
  "loc": "38.8200,-106.6603",
  "org": "AS40509 Fly.io, Inc.",
  "postal": "81210",
  "timezone": "America/Denver",
  "anycast": true
}
```

---

## Conclusion

The HoneyClaw SSH honeypot on 149.248.202.23:8022 is **not operational**. The service accepts TCP connections but fails to complete the SSH protocol handshake, resetting all connections before any authentication can occur.

Before deployment:
1. Debug why SSH handshake fails
2. Verify the SSH service sends proper banner
3. Test that password authentication works (and logs attempts)
4. Address IP fingerprinting if stealth is required

**Current Status:** ❌ Not Ready for Deployment
