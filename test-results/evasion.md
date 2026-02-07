# HoneyClaw Evasion Detection Test Results

**Executor:** TEST EXECUTOR 5  
**Target:** 149.248.202.23:8022  
**Date:** 2026-02-07  
**Status:** ⚠️ CRITICAL ISSUES FOUND

---

## Executive Summary

**Can an attacker detect this is a honeypot?** 

**YES - EASILY.** The current implementation has multiple critical fingerprinting vulnerabilities that would allow even an unsophisticated attacker to identify this as a honeypot within seconds.

---

## Test Results

### E-01: Timing Analysis

**10 Connection Samples:**

| Sample | Duration | Response |
|--------|----------|----------|
| 1 | 3.286s | `kex_exchange_identification: read: Connection reset by peer` |
| 2 | 3.447s | `kex_exchange_identification: read: Connection reset by peer` |
| 3 | 3.556s | `kex_exchange_identification: read: Connection reset by peer` |
| 4 | 3.635s | `kex_exchange_identification: read: Connection reset by peer` |
| 5 | 3.115s | `kex_exchange_identification: read: Connection reset by peer` |
| 6 | 3.275s | `kex_exchange_identification: read: Connection reset by peer` |
| 7 | 3.310s | `kex_exchange_identification: read: Connection reset by peer` |
| 8 | 3.405s | `kex_exchange_identification: read: Connection reset by peer` |
| 9 | 3.467s | `kex_exchange_identification: read: Connection reset by peer` |
| 10 | 3.631s | `kex_exchange_identification: read: Connection reset by peer` |

**Analysis:**
- Mean response time: ~3.4s (σ ≈ 0.15s)
- ⚠️ **All connections reset during key exchange** - authentication never reached
- Timing is consistent but the failure mode is highly suspicious

**Verdict:** 🔴 FAILS - Connection reset during KEX is not normal SSH behavior

---

### E-02: Behavioral Fingerprinting

**SSH Banner Comparison:**

| Server | Banner | Behavior |
|--------|--------|----------|
| HoneyClaw (8022) | `(empty)` | Does NOT send banner first |
| GitHub (22) | `SSH-2.0-ae0a932\r\n` | Sends banner immediately |

**Protocol Analysis:**
```
[Raw socket connection results]

1. Server sends on connect: b'' (empty - no banner)
2. After client sends SSH version: Connection reset by peer
3. Real SSH servers (e.g., GitHub): Send banner immediately upon connection
```

**Detection Vector #1 - Missing Server Banner:**
- Real SSH: Server sends `SSH-2.0-<identifier>` immediately
- HoneyClaw: Sends nothing, waits for client, then resets

**Detection Vector #2 - Connection Reset Timing:**
```
connect=0.005s → banner_wait=1s → send_version → reset_at=~2.3s
```
- After client sends version string, honeypot takes ~2.3s before resetting
- This delay pattern is identifiable and unusual

**Verdict:** 🔴 FAILS - Protocol behavior fundamentally broken

---

### E-03: Error Message Analysis

**Test Inputs and Responses:**

| Input Type | Expected (Real SSH) | HoneyClaw Response |
|------------|---------------------|-------------------|
| HTTP request | "Protocol mismatch" or similar error | Connection reset |
| SSH-1.0 version | Protocol version error | Connection reset |
| Binary garbage | Disconnect or error | Connection reset |

**Analysis:**
- All malformed inputs result in identical `Connection reset by peer`
- Real SSH servers typically send disconnect messages with reason codes
- Lack of differentiated error handling is a fingerprint

**Verdict:** 🟡 SUSPICIOUS - Uniform error handling reveals non-standard implementation

---

### E-04: Keyboard-Interactive Auth

**Test Command:**
```bash
ssh -o PreferredAuthentications=keyboard-interactive -p 8022 test@149.248.202.23
```

**Result:**
```
debug1: Local version string SSH-2.0-OpenSSH_10.0
kex_exchange_identification: read: Connection reset by peer
```

**Analysis:**
- Cannot test keyboard-interactive auth because connection fails at KEX stage
- Never reaches authentication negotiation

**Verdict:** 🔴 NOT TESTABLE - KEX failure blocks all auth testing

---

### E-05: Public Key Auth

**Test Command:**
```bash
ssh -o PreferredAuthentications=publickey -p 8022 test@149.248.202.23
```

**Result:**
```
debug1: Local version string SSH-2.0-OpenSSH_10.0
kex_exchange_identification: read: Connection reset by peer
```

**Analysis:**
- Same failure as E-04 - connection dies at key exchange
- Public key authentication never attempted

**Verdict:** 🔴 NOT TESTABLE - KEX failure blocks all auth testing

---

## Critical Detection Vectors

### 1. 🚨 No Server Banner (CRITICAL)
**What Gives It Away:** Real SSH servers send their version banner (`SSH-2.0-xxx`) immediately upon TCP connection. HoneyClaw sends nothing.

**Detection Method:**
```python
sock.connect((target, 8022))
data = sock.recv(1024)  # Real SSH: banner. HoneyClaw: empty
if not data.startswith(b'SSH-'):
    print("HONEYPOT DETECTED")
```

### 2. 🚨 KEX Failure (CRITICAL)
**What Gives It Away:** Connection resets during key exchange identification. Real SSH completes KEX, proceeds to auth, then rejects bad credentials.

**Detection Method:**
```bash
ssh -v target 2>&1 | grep -q "kex_exchange_identification.*reset"
# If true: likely honeypot or severely misconfigured
```

### 3. ⚠️ Uniform Error Response
**What Gives It Away:** All protocol errors result in connection reset, no SSH disconnect messages with reason codes.

### 4. ⚠️ Timing Pattern
**What Gives It Away:** ~2.3s delay between receiving client version and resetting. This precise timing could be fingerprinted.

---

## Comparison: Expected vs Actual Behavior

| Phase | Real OpenSSH | HoneyClaw |
|-------|--------------|-----------|
| Connect | Accept TCP | Accept TCP ✓ |
| Server Banner | Send `SSH-2.0-xxx` immediately | Send nothing ✗ |
| Client Banner | Receive client version | Receive, then... |
| KEX Init | Exchange algorithms | Reset connection ✗ |
| Auth | Negotiate methods | Never reached ✗ |
| Password prompt | Request credentials | Never reached ✗ |

---

## Recommendations for Better Mimicry

### Priority 1: Fix Protocol Compliance (CRITICAL)

1. **Send SSH Banner Immediately**
   ```
   On TCP accept: send "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
   ```
   - Use a common, real-world banner string
   - Add OS/distro info for authenticity

2. **Complete Key Exchange**
   - Implement proper KEX negotiation
   - Support standard algorithms: curve25519-sha256, ecdh-sha2-nistp256
   - Exchange host keys, complete Diffie-Hellman

3. **Reach Authentication Phase**
   - After KEX, send auth methods: `publickey,password,keyboard-interactive`
   - Actually prompt for password before rejecting/accepting

### Priority 2: Realistic Error Handling

4. **Differentiated Error Messages**
   - Invalid protocol: `Protocol mismatch.` then close
   - Old SSH version: `Protocol major versions differ`
   - Bad auth: `Permission denied (publickey,password).`

5. **Use SSH Disconnect Messages**
   - Send proper SSH_MSG_DISCONNECT with reason codes
   - Code 2: Protocol error
   - Code 11: By application

### Priority 3: Timing Randomization

6. **Add Jitter to Responses**
   - Vary response times by ±100-500ms
   - Avoid consistent 2.3s reset pattern

7. **Simulate Network Latency**
   - Add realistic delays matching geographic location
   - Consider time-of-day variance

### Priority 4: Advanced Mimicry

8. **Match Real OpenSSH Fingerprints**
   - SSH-keyscan should return believable host keys
   - Support same ciphers/MACs as target OpenSSH version

9. **Implement Tarpitting**
   - Slow password prompts to waste attacker time
   - Multiple "incorrect password" before lockout

10. **Behavioral Consistency**
    - After N failed auths, close with proper message
    - Rate limit like real SSH (`MaxAuthTries`)

---

## Tools for Detection (Attacker Perspective)

These tools/commands would detect HoneyClaw in its current state:

```bash
# 1. Banner check (instant detection)
echo | nc -w 3 target 8022 | head -1
# Empty = honeypot

# 2. SSH version exchange test
ssh -v target -p 8022 2>&1 | grep "kex_exchange_identification"
# "Connection reset" = honeypot

# 3. Nmap SSH scan
nmap -sV -p 8022 target --script ssh2-enum-algos
# Failure to enumerate = honeypot

# 4. Shodan/Censys fingerprint
# Would show anomalous SSH implementation
```

---

## Conclusion

**Current State:** The honeypot is trivially detectable. It fails at the most basic SSH protocol handshake, never reaching the credential capture phase.

**Root Cause:** The SSH implementation appears incomplete - it accepts connections but crashes/resets during key exchange, before any meaningful interaction.

**Immediate Action Required:**
1. Fix SSH protocol compliance (banner + KEX)
2. Reach authentication phase
3. Capture credentials before closing connection

**Sophistication Level Required to Detect:** 
- Current: **Trivial** (any SSH client reveals it)
- Target: Should require specialized honeypot detection tools

---

*Test completed: 2026-02-07 09:29 PST*
