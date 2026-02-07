# Defensive Security Review

## Overall Assessment

This test plan demonstrates a solid foundation for honeypot deployment, but **falls short of SOC operational requirements**. The logging tests (L-01 through L-05) cover only basic structural concerns—timestamp presence, JSON validity, persistence—without addressing the enrichment, normalization, and context that make honeypot data *actionable* for defenders. A SOC analyst receiving these logs would need to perform significant manual triage before they become useful for incident response.

The plan also lacks tests for alert fidelity, false positive handling, and integration with threat intelligence feeds. From a blue team perspective, a honeypot that generates logs without context is just noise. We need logs that tell a story: who's attacking, what TTPs they're using, how this correlates with other indicators, and what action to take.

## Strengths

- **Rate limiting tests (R-01–R-05)** are well-designed—essential for preventing honeypot abuse and ensuring log fidelity
- **Input validation tests (I-01–I-07)** protect log integrity; log injection attacks (I-05) would be catastrophic for SIEM
- **MITRE tagging mentioned in A-01** indicates awareness of TTP mapping (critical for threat intel)
- **Correlation IDs (L-05)** enable session reconstruction—essential for IR
- **Attack simulation category (A-01–A-05)** tests realistic adversary behavior, not just edge cases
- **Log persistence test (L-02)** ensures we don't lose evidence on container restart

## Logging Gaps

- **No test for GeoIP enrichment** — "Who" matters; IP alone is useless without geo/ASN context
- **No test for threat feed correlation** — Does the log indicate if source IP is on known bad lists?
- **No test for SSH client fingerprinting** — Client version/algorithm negotiation reveals attacker tooling
- **No test for session transcript capture** — Post-auth, what commands do they try? (if ever successful)
- **No test for credential frequency/novelty** — Is this a new password we haven't seen, or same wordlist?
- **No test for connection metadata** — TLS/SSH cipher negotiated, key exchange type, compression
- **No test for reverse DNS logging** — PTR records can indicate C2 infrastructure
- **No normalized severity/priority field** — How urgent is this event?

## SIEM Integration Concerns

| Concern | Impact | Mitigation |
|---------|--------|------------|
| No Common Event Format (CEF/LEEF) test | Major SIEM vendors expect CEF; raw JSON requires custom parsing | Add test for CEF output or syslog RFC5424 compliance |
| No timestamp format validation | ISO8601 with timezone required; ambiguous timestamps break correlation | Test for `2026-02-07T09:27:00.000Z` format specifically |
| Missing source_type/index routing field | Splunk/Elastic need metadata for routing | Test that logs include `event.type`, `event.category` (ECS) |
| No ingestion latency test | Real-time alerting needs <5s log delivery | Add test measuring log→SIEM latency |
| Large field values (10KB in I-01/I-02) | May exceed SIEM field limits (Splunk 32KB, Elastic varies) | Validate truncation creates valid log, not corrupted event |
| No test for log volume estimation | SOC needs capacity planning; what's normal vs attack volume? | Add sustained load test with events/minute metrics |

## Alert Quality Issues

- **L-04 only tests "alert sent"** — Doesn't test if alert contains actionable context
- **No false positive rate testing** — What triggers alerts vs. what should? Scanner noise vs. targeted attack?
- **No alert threshold tuning tests** — At what volume does single IP become "campaign"?
- **No alert aggregation testing** — 1000 attempts from same IP should be 1 alert, not 1000
- **No escalation logic testing** — When does alert become "page the on-call"?
- **No test for alert fatigue prevention** — Repeated alerts for same campaign waste analyst attention
- **Webhook test (L-04) doesn't validate payload schema** — What fields does the webhook include? Is it parseable?

## Test Improvements

| Test ID | Current | Suggested Improvement |
|---------|---------|----------------------|
| L-01 | "Check all events logged" | Specify exact required fields: `src_ip`, `src_port`, `dst_port`, `timestamp`, `session_id`, `event_type`, `mitre_tactic`, `mitre_technique`, `geo_country`, `geo_asn`, `threat_intel_match` |
| L-03 | "Valid JSON, consistent schema" | Add ECS (Elastic Common Schema) or OCSF compliance check; validate against JSON Schema |
| L-04 | "Alert sent to webhook" | Validate alert includes: severity, kill-chain phase, recommended action, source context, deduplication key |
| A-01 | "All logged with MITRE tags" | Specify required tags: `T1078` (Valid Accounts), `T1110` (Brute Force), tactic should be `TA0006` (Credential Access) |
| A-05 | "Still captured despite timing" | Define "low-and-slow" quantitatively: 1 attempt/5min over 24h should still correlate as single campaign |
| E-02 | "Mimics real OpenSSH behavior" | Test with `ssh-audit` tool to generate OpenSSH similarity score; document accepted deviation |
| R-03 | "Block event logged with IP, count, limit" | Should also log: time window, previous attempt count, recommended block duration |

## Additional Tests Recommended

| New Test | Description | Priority |
|----------|-------------|----------|
| L-06: GeoIP Enrichment | Verify logs include `geo.country_iso_code`, `geo.city_name`, `geo.as_org` | HIGH |
| L-07: Threat Intel Lookup | Test that known-bad IPs (from OTX, AbuseIPDB) are flagged in log | HIGH |
| L-08: ECS/OCSF Compliance | Validate log schema matches Elastic Common Schema v8 or OCSF 1.0 | HIGH |
| L-09: Syslog Output | Test RFC5424 syslog output for legacy SIEM integration | MEDIUM |
| L-10: Log Sampling Accuracy | Under 10K events/min, validate no events dropped | HIGH |
| A-06: Credential Intelligence | Log should indicate if password matches common wordlists (rockyou, etc.) | MEDIUM |
| A-07: Attack Campaign Correlation | Multiple IPs using same password list should correlate as campaign | HIGH |
| A-08: Time-of-Day Analysis | Verify logs support temporal analysis (attacker timezone inference) | LOW |
| ALT-01: Alert Aggregation | 100 events from same IP in 1 minute = 1 aggregated alert | HIGH |
| ALT-02: Alert Severity Mapping | Credential stuffing = MEDIUM, targeted brute force = HIGH, post-auth activity = CRITICAL | HIGH |
| ALT-03: Alert Deduplication | Same source resuming after 1h gap = continuation, not new alert | MEDIUM |
| INT-01: Splunk HEC Test | POST logs to Splunk HTTP Event Collector, validate indexing | MEDIUM |
| INT-02: Elastic Integration | Ship to Elasticsearch, verify field mapping and searchability | MEDIUM |
| INT-03: SOAR Webhook | Trigger TheHive/Shuffle/SOAR case creation from alert | MEDIUM |
| TI-01: IOC Extraction | Auto-extract IOCs (IPs, credentials) for threat intel sharing | MEDIUM |

## Recommended Log Schema (Minimum Fields)

For SOC utility, each authentication event should include:

```json
{
  "@timestamp": "2026-02-07T17:27:00.000Z",
  "event.kind": "event",
  "event.category": ["authentication"],
  "event.type": ["start"],
  "event.outcome": "failure",
  "event.severity": 3,
  
  "source.ip": "45.33.32.156",
  "source.port": 54321,
  "source.geo.country_iso_code": "US",
  "source.geo.city_name": "Fremont",
  "source.as.number": 63949,
  "source.as.organization.name": "Linode",
  
  "destination.port": 8022,
  
  "user.name": "root",
  "honeyclaw.password_hash": "sha256:abc123...",
  "honeyclaw.password_in_wordlist": true,
  "honeyclaw.client_version": "SSH-2.0-libssh2_1.10.0",
  
  "threat.indicator.ip": "45.33.32.156",
  "threat.feed.name": "AbuseIPDB",
  "threat.feed.match": true,
  
  "mitre.tactic": "credential-access",
  "mitre.technique": "T1110.001",
  "mitre.technique_name": "Brute Force: Password Guessing",
  
  "session.id": "abc123-session-uuid",
  "observer.name": "honeyclaw-ssh",
  "observer.type": "honeypot"
}
```

## Defensive Value Assessment

**Current Value:** LOW-MEDIUM  
The honeypot will capture attacker credentials and IPs, but without the recommended enrichments, a SOC analyst must manually:
1. Look up GeoIP for every source IP
2. Check threat feeds manually
3. Correlate attempts without campaign detection
4. Parse raw JSON without SIEM-native formatting

**Potential Value:** HIGH  
With recommended improvements, this becomes a high-fidelity early warning system:
- Detects credential stuffing before production systems are hit
- Identifies threat actors casing the environment  
- Provides threat intel (credential lists, source IPs) for proactive blocking
- Feeds SOAR playbooks for automated response

## Detection Rule Tuning Recommendations

Based on this honeypot's data, I would create these SIEM detection rules:

1. **Single IP Brute Force**: >20 attempts from same IP in 5min → MEDIUM alert
2. **Distributed Brute Force**: >5 IPs using same credentials in 1hr → HIGH alert (credential reuse campaign)
3. **Known-Bad Source**: Any connection from threat-intel-flagged IP → HIGH alert
4. **Novel Credential**: Password not in known wordlists → MEDIUM alert (possible targeted attack)
5. **Reconnaissance Spike**: >50% increase in unique source IPs vs baseline → INFO alert
6. **APT Pattern**: Same source, <5 attempts/day, >7 days duration → HIGH alert (slow-burn attack)

## Blue Team Verdict

- [ ] APPROVE plan as-is
- [x] APPROVE with modifications
- [ ] REJECT - major gaps

**Conditions for Approval:**
1. Add L-06 (GeoIP), L-07 (Threat Intel), L-08 (ECS compliance) — these are **non-negotiable** for SOC use
2. Add ALT-01 (Alert Aggregation) — without this, the honeypot creates alert fatigue
3. Document expected log schema in test plan, not just "valid JSON"
4. Add at least one SIEM integration test (Splunk HEC or Elastic)

**The Bottom Line:** This test plan ensures the honeypot *works*. It doesn't ensure the honeypot *helps defenders*. Add the logging enrichment tests, and you have a valuable SOC tool. Without them, you have a JSON generator.

---

*Reviewed by: Blue Team Security Specialist*  
*Date: 2026-02-07*  
*Review Time: ~45 minutes*
