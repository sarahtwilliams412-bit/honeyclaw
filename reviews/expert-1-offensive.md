# Offensive Security Review

## Overall Assessment

This test plan covers the basics but **would not fool an experienced attacker**. The plan tests what the honeypot *does*, but not whether it *looks real*. Any competent red teamer runs fingerprinting tools before engaging a target—Shodan, Censys, and custom scripts that detect honeypots in seconds. The plan has zero tests for these detection vectors. The attack simulations are script-kiddie level: dictionary attacks and credential stuffing are what automated botnets do, not targeted threat actors.

The input validation and protocol tests are reasonable for a v1, but they miss the nuanced behavior differences that give away honeypots. Real OpenSSH has quirks accumulated over decades. Does HoneyClaw replicate the exact algorithm negotiation order? The specific timing jitter? The obscure error codes for edge cases? I'd bet money it doesn't, and the plan doesn't test for it.

## Strengths

- Solid coverage of basic functional requirements
- Rate limiting tests are thorough
- Input validation covers common injection vectors
- Operational resilience testing is appropriate for production
- MITRE tagging for attack simulation is good practice
- Test phasing is logical and time-boxed

## Missing Attack Vectors

- **Shodan/Censys Fingerprinting**: Honeypots have known signatures. No test checks if HoneyClaw appears in honeypot databases or matches known patterns.
- **SSH Algorithm Ordering**: Real OpenSSH has specific algorithm preference orders. Honeypots often use library defaults that differ.
- **TCP/IP Stack Fingerprinting**: The claimed OS (Ubuntu) should have a matching TCP fingerprint (nmap -O). Likely doesn't.
- **Post-Auth Behavior**: What if auth *succeeds*? Attackers test with known credentials. If the shell looks fake, game over.
- **SSH Subsystem Requests**: sftp, scp, netconf—real servers respond specifically. Honeypots often reject or behave oddly.
- **Channel Multiplexing**: Real SSH supports multiple channels. Does HoneyClaw? Attackers test this.
- **Agent Forwarding Requests**: Attackers probe for agent forwarding to detect honeypots that don't implement it.
- **Compression Negotiation**: Request compression, send data—honeypots often don't implement zlib correctly.
- **HostKey Rotation Detection**: Same hostkey across restarts is expected, but if it matches other known honeypots, it's flagged.
- **Mirai/Botnet Behavior Simulation**: Automated scanners have specific patterns. Does HoneyClaw look attractive to them?
- **Exit-Status Probing**: After auth, request specific exit statuses. Honeypots return wrong values.

## Honeypot Detection Risks

| Detection Method | Risk Level | Notes |
|------------------|------------|-------|
| Shodan "honeypot" tag | **CRITICAL** | Shodan auto-tags known honeypots. Is HoneyClaw flagged? |
| Banner inconsistency | HIGH | Banner says Ubuntu but behavior doesn't match |
| Algorithm ordering | HIGH | Default golang.org/x/crypto/ssh ordering differs from OpenSSH |
| Timing precision | HIGH | Emulated systems have nanosecond-level timing tells |
| TCP fingerprint | MEDIUM | `nmap -O` will reveal if TCP stack doesn't match claimed OS |
| Too-perfect responses | MEDIUM | Real systems have jitter; honeypots are often deterministic |
| Missing features | MEDIUM | No agent forwarding, no subsystems = obvious honeypot |
| Hostkey in databases | MEDIUM | Same hostkey as other honeypots = instant detection |
| Fail2ban absence | LOW | Real servers usually have fail2ban; honeypots often don't rate-limit correctly |
| Response to gibberish | LOW | Real SSH has specific error for each malformed packet type |

## Test Improvements

| Test ID | Current | Suggested Improvement |
|---------|---------|----------------------|
| E-01 | "Measure response timing consistency" | Measure timing at nanosecond precision across 1000+ requests. Compare variance to real OpenSSH. Timing should include network jitter simulation. |
| E-02 | "Test SSH implementation quirks" | Specifically test: algorithm ordering, KEX negotiation order, response to deprecated algorithms, handling of uncommon cipher requests |
| E-03 | "Trigger various errors" | Document exact expected error strings. Compare byte-for-byte to real OpenSSH 8.9p1 responses. Test: bad version string, bad KEX init, bad auth method |
| E-04 | Keyboard-Interactive test | Test multi-round keyboard-interactive with PAM-style prompts. Real OpenSSH has specific behavior here. |
| E-05 | Public Key Auth | Test with valid key, invalid key, and wrong algorithm. Check error messages match real OpenSSH exactly. |
| P-01 | "Malformed packets" | Fuzz with AFL or libfuzzer. Specific tests: truncated packets at each protocol phase, oversized packets, wrong packet types |
| P-03 | "Cipher downgrade" | Test full list: arcfour, 3des-cbc, blowfish-cbc. Real OpenSSH rejects these with specific messages. |
| A-05 | "Low-and-slow attempts" | Test over 24h, 1 attempt per hour. Test from multiple IPs with similar patterns. This is APT behavior. |
| I-05 | "Log injection" | Test CRLF injection, ANSI escape sequences, UTF-8 overlong encodings, and BOM characters |

## Additional Tests Recommended

| New Test | Description | Priority |
|----------|-------------|----------|
| D-01 Shodan Detection | Query Shodan API for our IP. Check if tagged as honeypot. | CRITICAL |
| D-02 Algorithm Ordering | Capture full KEX and compare algorithm lists to real OpenSSH 8.9p1 | CRITICAL |
| D-03 TCP Fingerprint | Run `nmap -O` and verify OS detection matches claimed Ubuntu | HIGH |
| D-04 Hostkey Uniqueness | Hash hostkey, search Shodan/Censys for duplicates | HIGH |
| D-05 Post-Auth Shell | Configure test creds, verify shell environment looks real | HIGH |
| D-06 Subsystem Handling | Request sftp, exec, shell subsystems—compare to real OpenSSH | HIGH |
| D-07 Version Behavior Match | Test 20+ edge cases against real OpenSSH 8.9p1 and diff responses | HIGH |
| D-08 Agent Forwarding | Request agent forwarding, verify behavior matches OpenSSH | MEDIUM |
| D-09 Port Forwarding | Request local/remote forwarding, check response | MEDIUM |
| D-10 Channel Stress | Open 10 channels simultaneously, verify handling | MEDIUM |
| D-11 Compression Bomb | Enable compression, send highly compressible data | MEDIUM |
| D-12 Timezone Consistency | Check if logged timestamps/system responses match claimed TZ | LOW |
| D-13 Known Credential Test | Try root:root, admin:admin—these should log but not obviously bait | LOW |

## Attack Simulation Gaps

The current attack simulations (A-01 through A-05) are **botnet-level attacks**. Here's what's missing:

### Targeted Threat Actor Simulation
| Attack Pattern | Description |
|----------------|-------------|
| Recon-first | Shodan lookup → Banner grab → Timing test → Only then auth |
| Credential validation | Try known leaked creds for this "organization" |
| Lateral pivot | Credentials that would indicate prior compromise elsewhere |
| Living-off-the-land | If auth succeeds, test for common binaries (curl, wget, python) |
| Data exfil test | If shell provided, attempt outbound connection |

### Red Team Playbook (What I Would Do)
1. `shodan host 149.248.202.23` — Check for honeypot tags
2. `nmap -sV -O -p8022 149.248.202.23` — Full fingerprint
3. Custom script: connect, request algorithms, compare to OpenSSH baseline
4. Timing analysis: 100 connections, measure response variance
5. Banner analysis: compare exact bytes to real OpenSSH 8.9p1
6. If still looks legit: single auth attempt with throwaway creds
7. Monitor for any "too eager" logging behavior (honeypots log too fast)
8. Check if rate limiting matches real fail2ban behavior

## Critical Vulnerabilities in Test Plan

1. **No baseline comparison**: Tests check if honeypot "works" but not if it's distinguishable from real SSH. You need a parallel test against a real OpenSSH 8.9p1 instance.

2. **Evasion tests are superficial**: E-01 through E-05 are checkbox tests. Real evasion detection requires byte-level comparison against reference implementations.

3. **No external perspective**: All tests are from the attacker's connection. What does the honeypot look like from Shodan/Censys? From BGP routing perspective?

4. **Rate limiting is a tell**: Real SSH servers with fail2ban behave differently than custom rate limiting. Test if the rate limit responses match fail2ban exactly.

5. **Missing "is this worth attacking" test**: Before attacking, I'd check if the target has anything valuable. Does HoneyClaw present a believable system with interesting services/files?

## Red Team Verdict

- [ ] APPROVE plan as-is
- [x] APPROVE with modifications
- [ ] REJECT - major gaps

**Conditional approval.** The plan is adequate for functional testing but insufficient for deception validation. Before deployment:

1. **MUST ADD**: Shodan/Censys fingerprint check (D-01)
2. **MUST ADD**: Algorithm ordering comparison (D-02)  
3. **MUST ADD**: TCP fingerprint verification (D-03)
4. **SHOULD ADD**: Post-auth behavior tests if any auth succeeds (D-05)
5. **SHOULD ADD**: Real OpenSSH baseline comparison for all E-* tests

Without these additions, an experienced attacker will identify this as a honeypot within 30 seconds. The current test plan validates that the honeypot *functions*—it does not validate that the honeypot *deceives*.

---

*Reviewed by: Offensive Security Specialist (Red Team)*  
*Date: 2026-02-07*  
*Classification: APPROVE WITH MODIFICATIONS*
