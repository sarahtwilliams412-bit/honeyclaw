# HoneyClaw Improvement Plan: Production-Grade Honeypot Architecture

**Created:** 2026-02-07
**Based on:** Modern honeypot architecture research & gap analysis against current codebase
**Status:** Approved for implementation

---

## Executive Summary

HoneyClaw already has a strong foundation with comprehensive logging, real-time alerting, threat intelligence enrichment, session replay, SIEM integrations, and geo-distributed mesh capabilities. This plan identifies **critical gaps** that separate the current implementation from a production-grade threat intelligence platform suitable for sensitive data environments.

### Current State vs. Target State

| Capability | Current State | Target State | Gap Severity |
|---|---|---|---|
| Network isolation | Documented, basic Docker bridge | VPC/VNet with IaC enforcement | **HIGH** |
| Automated rebuilds | Manual | Scheduled IaC teardown/rebuild cycles | **HIGH** |
| Log immutability | S3 storage available | S3 Object Lock + versioning | **MEDIUM** |
| MITRE ATT&CK mapping | Schema fields defined | Full event tagging pipeline | **MEDIUM** |
| AI adaptive deception | Module stub exists | Sophistication-aware responses | **HIGH** |
| Stateful interaction | SSH/API respond to commands | Full filesystem + process emulation | **HIGH** |
| Health monitoring | None | Self-healing with compromise detection | **CRITICAL** |
| Anti-fingerprinting | None | Timing jitter, banner rotation | **HIGH** |
| Kubernetes orchestration | None | Auto-scaling pod deployment | **MEDIUM** |
| Malware analysis pipeline | None | Automated sandbox + IoC extraction | **MEDIUM** |
| STIX/TAXII export | Mentioned in architecture | Working implementation | **LOW** |
| End-to-end testing | Partial unit tests | Full integration + anti-detection tests | **HIGH** |
| SOAR integration | None | Playbook triggers + automated response | **MEDIUM** |
| Compliance automation | Legal docs exist | Automated retention + anonymization | **MEDIUM** |

---

## Phase 1: Critical Security & Reliability (P0)

### 1.1 Health Monitoring & Compromise Detection

**Gap:** No system exists to detect if a honeypot has been compromised or is malfunctioning. A silent failure means blind spots in threat detection; a compromised honeypot can become attack infrastructure.

**Implementation:**

Create `src/health/monitor.py`:
- Periodic health checks for all active honeypot services
- Verify services are responding on expected ports
- Verify logging pipeline is functional (write test event, confirm receipt)
- Verify network isolation is intact (attempt outbound connection, confirm blocked)
- Monitor resource usage (CPU, memory, disk, open file descriptors)
- Detect compromise indicators:
  - Unexpected outbound connections
  - Filesystem modifications outside expected paths
  - New processes not in the allow-list
  - Unexpected cron jobs or persistence mechanisms
  - Rootkit detection (hidden processes, modified binaries)

Create `src/health/self_heal.py`:
- Automated response to health check failures
- Trigger container rebuild on compromise detection
- Alert SOC team on any anomaly
- Snapshot container state for forensic analysis before teardown

**Health check endpoint spec:**
```
GET /health
{
  "status": "healthy|degraded|compromised",
  "services": {
    "ssh": {"status": "up", "connections_active": 3},
    "api": {"status": "up", "requests_last_hour": 142},
    "logging": {"status": "up", "events_last_hour": 287},
    "enrichment": {"status": "degraded", "reason": "abuseipdb rate limited"}
  },
  "isolation": {
    "egress_blocked": true,
    "no_shared_credentials": true,
    "filesystem_integrity": true
  },
  "resources": {
    "cpu_percent": 12.3,
    "memory_mb": 64,
    "disk_percent": 23.1,
    "open_fds": 47
  },
  "last_check": "2026-02-07T10:00:00Z"
}
```

**Affected files:**
- New: `src/health/monitor.py`, `src/health/self_heal.py`, `src/health/__init__.py`
- Modified: `src/cli/main.py` (add `honeyclaw health` command)
- Modified: all template entrypoints (register health check hooks)

**Success criteria:**
- Health checks run every 60 seconds
- Compromise detected within 5 minutes of occurrence
- Automated rebuild triggered within 10 minutes
- Zero false positives in health monitoring over 7-day test period

---

### 1.2 Infrastructure-as-Code for Automated Rebuild Cycles

**Gap:** No IaC templates exist for reproducible deployment. Current deployment relies on manual Docker commands and Fly.io CLI. Without automated rebuilds, a compromised honeypot can persist indefinitely.

**Implementation:**

Create `deploy/terraform/`:
- `main.tf` - Core infrastructure definition
- `variables.tf` - Configurable parameters (region, instance type, template)
- `modules/honeypot/` - Reusable honeypot module
- `modules/networking/` - VPC, subnets, security groups, NACLs
- `modules/logging/` - S3 buckets with Object Lock, CloudWatch

Create `deploy/flyio/`:
- `fly.toml` templates per honeypot type
- `deploy.sh` - Automated deployment script with health verification
- `rotate.sh` - Scheduled teardown and rebuild script

Create `deploy/kubernetes/`:
- `helm/honeyclaw/` - Helm chart for Kubernetes deployment
- CronJob for automated pod rotation every 24 hours
- NetworkPolicy for strict egress control
- PodSecurityPolicy / Pod Security Standards

**Rebuild cycle spec:**
- Default: rebuild every 24 hours
- Configurable via `HONEYCLAW_REBUILD_INTERVAL_HOURS`
- Pre-rebuild: export session data and forensic snapshot
- Post-rebuild: verify all services healthy before accepting traffic
- Emergency rebuild: triggered by health monitor compromise detection

**Affected files:**
- New: `deploy/terraform/`, `deploy/flyio/`, `deploy/kubernetes/`
- Modified: `scripts/` (integrate with IaC lifecycle)

**Success criteria:**
- Full infrastructure reproducible from single `terraform apply`
- Automated 24-hour rebuild cycle with zero downtime (blue-green)
- Rebuild completes and passes health checks within 5 minutes

---

### 1.3 Network Isolation Enforcement

**Gap:** Network isolation is documented in the threat model but not enforced programmatically. The Docker bridge network with "No ICC" is a start but insufficient for production sensitive environments.

**Implementation:**

Enhance `deploy/terraform/modules/networking/`:
- Dedicated VPC with no peering to production
- Private subnets for honeypots, public subnets only for ingress
- NACLs with explicit deny-all egress except:
  - Log shipping to SIEM endpoint (specific IP + port)
  - Health check responses
  - DNS resolution (restricted to internal resolver)
- Security groups per honeypot template
- VPC Flow Logs enabled for forensic audit

Docker enhancement:
- AppArmor profile for each honeypot template
- Seccomp profile restricting syscalls
- Read-only root filesystem (already documented, verify enforced)
- Drop ALL capabilities, add back only what's needed
- `--pids-limit` to prevent fork bombs
- `--network=none` for containers that don't need network (processing)

Create `deploy/apparmor/`:
- `honeyclaw-ssh.profile`
- `honeyclaw-api.profile`
- `honeyclaw-enterprise.profile`

Create `deploy/seccomp/`:
- `honeyclaw-default.json` - minimal syscall allowlist

**Affected files:**
- New: `deploy/apparmor/`, `deploy/seccomp/`, Terraform networking modules
- Modified: Docker run commands in all deployment scripts
- Modified: `docker-compose.yml` files in templates

**Success criteria:**
- No outbound connections possible except to SIEM
- AppArmor/Seccomp violations logged and alerted
- VPC flow logs captured for all traffic
- Penetration test confirms isolation holds

---

## Phase 2: Enhanced Intelligence Gathering (P1)

### 2.1 Stateful Interaction & Realistic Environment

**Gap:** The SSH honeypot captures credentials and commands but returns limited responses. The fake API returns static JSON. Sophisticated attackers can fingerprint the honeypot within seconds by issuing standard recon commands and observing unrealistic responses.

**Implementation:**

Create `src/emulation/filesystem.py`:
- Generate realistic filesystem trees based on OS profile
- Fake `/etc/passwd`, `/etc/shadow`, `/etc/hosts`
- Realistic home directories with `.bash_history`, `.ssh/`, `.aws/`
- Configuration files with canary tokens embedded
- Process list simulation (`/proc/` entries)
- Size/permission/timestamp metadata

Create `src/emulation/shell.py`:
- State-aware shell emulator maintaining:
  - Current working directory
  - Environment variables
  - Command history
  - User context (uid, groups)
- Built-in command handlers:
  - `ls`, `cat`, `cd`, `pwd`, `whoami`, `id`, `uname`, `ps`, `netstat`
  - `wget`, `curl` (log URL, return fake download)
  - `sudo` (log escalation attempt, optionally "succeed")
  - `scp`, `ssh` (log lateral movement attempt)
- Command not found handler (realistic error messages)
- Pipe and redirect support (basic)

Create `src/emulation/timing.py`:
- Add realistic response delays
- Disk I/O simulation (larger files take longer to "read")
- Network latency simulation
- CPU load simulation (commands that would be CPU-intensive)
- Jitter to prevent timing fingerprinting

**OS profiles** (`src/emulation/profiles/`):
- `ubuntu-22.04.json` - Ubuntu LTS
- `centos-7.json` - CentOS/RHEL
- `debian-12.json` - Debian stable
- `amazon-linux-2.json` - AWS default

**Affected files:**
- New: `src/emulation/` package
- Modified: `templates/basic-ssh/honeypot.py` (integrate shell emulator)
- Modified: `templates/enterprise-sim/` (use emulation layer)

**Success criteria:**
- Standard recon commands (`uname -a`, `ls /`, `cat /etc/passwd`) return believable output
- Attacker dwell time increases by 3x compared to current static responses
- Honeypot passes basic Shodan/Censys fingerprint checks
- Canary tokens present in fake config files

---

### 2.2 AI Adaptive Deception

**Gap:** The AI conversational deception module exists as a stub (`src/ai/`) but lacks sophistication-aware behavior. All attackers receive the same interaction level regardless of whether they're script kiddies or APT operators.

**Implementation:**

Create `src/ai/classifier.py`:
- Real-time attacker sophistication scoring based on:
  - Command sequence patterns (automated vs manual)
  - Typing speed and patterns (key timing analysis)
  - Tool signatures (Metasploit, Cobalt Strike, custom)
  - Evasion technique usage
  - Knowledge of system internals
- Classification levels:
  - `AUTOMATED` (score 0.0-0.2): bots, scanners
  - `SCRIPT_KIDDIE` (score 0.2-0.4): copy-paste exploits
  - `SKILLED` (score 0.4-0.7): manual ops, some evasion
  - `ADVANCED` (score 0.7-0.9): custom tools, good OPSEC
  - `APT` (score 0.9-1.0): state-level TTPs

Create `src/ai/adapter.py`:
- Adjust interaction level based on classification:
  - `AUTOMATED`: low-interaction, fast responses, collect IoCs
  - `SCRIPT_KIDDIE`: medium-interaction, appear vulnerable
  - `SKILLED`: high-interaction, AI conversation, fake data breadcrumbs
  - `ADVANCED/APT`: maximum engagement, realistic environment, alert SOC immediately
- Dynamic response generation using conversation context
- Personality profiles (confused intern, paranoid admin, careless developer)
- Breadcrumb system: plant increasingly valuable-looking fake data to extend engagement

**Affected files:**
- New: `src/ai/classifier.py`, `src/ai/adapter.py`
- Modified: `src/ai/` existing module (integrate classification)
- Modified: `templates/basic-ssh/honeypot.py` (wire up adaptive responses)

**Success criteria:**
- Correct classification of attacker sophistication within 5 commands
- Advanced attackers engage 5x longer than with static responses
- Zero real secrets exposed regardless of engagement level
- APT-level alerts reach SOC within 30 seconds

---

### 2.3 MITRE ATT&CK Full Mapping

**Gap:** The log schema includes `mitre_tactics` and `mitre_techniques` fields, but these aren't populated consistently across all event types. Downstream SIEM rules reference MITRE IDs but many events arrive untagged.

**Implementation:**

Create `src/analysis/mitre_mapper.py`:
- Comprehensive mapping of observed behaviors to MITRE ATT&CK:
  - `T1078` - Valid Accounts (successful honeypot auth)
  - `T1110` - Brute Force (credential stuffing)
  - `T1059` - Command and Scripting Interpreter (shell commands)
  - `T1021` - Remote Services (SSH, RDP, WinRM)
  - `T1083` - File and Directory Discovery (`ls`, `find`)
  - `T1005` - Data from Local System (`cat` sensitive files)
  - `T1041` - Exfiltration Over C2 (`wget`, `curl` to external)
  - `T1548` - Abuse Elevation Control (`sudo`, SUID)
  - `T1055` - Process Injection (container escape patterns)
  - `T1190` - Exploit Public-Facing Application (API exploits)
- Auto-tag events as they flow through the logging pipeline
- Support for custom mapping rules via configuration

**Affected files:**
- New: `src/analysis/mitre_mapper.py`, `src/analysis/mitre_rules.yaml`
- Modified: `src/alerts/rules.py` (enrich alerts with MITRE context)
- Modified: all template loggers (pass events through mapper)
- Modified: SIEM integration modules (include MITRE fields)

**Success criteria:**
- 95%+ of events have at least one MITRE tactic/technique tagged
- SIEM dashboards can filter and aggregate by MITRE ATT&CK
- Attack chain visualization possible from tagged events

---

### 2.4 Enhanced Logging: Correlation & Immutability ✅ IMPLEMENTED

**Gap:** Events lack correlation IDs for tracking multi-step attacks. S3 storage doesn't use Object Lock for tamper-proof retention. Geolocation isn't consistently applied at log time.

**Implementation:**

Enhance `src/utils/` and logging pipeline:
- **Correlation IDs:** Generate `session_correlation_id` on first connection, propagate across all events from same source IP within a time window. Track attack chains across services (e.g., port scan -> SSH brute force -> API exploit).
- **Log immutability:** Configure S3 buckets with:
  - Object Lock in Compliance mode
  - Versioning enabled
  - Lifecycle rules for retention
  - Cross-region replication for disaster recovery
- **Geolocation at ingest:** Use MaxMind GeoLite2 for IP geolocation at event creation time. Fields: country, city, ASN, organization, latitude/longitude.
- **Backup log stream:** Secondary log destination (different provider/account) as insurance against primary compromise.

**Affected files:**
- Modified: `src/replay/recorder.py` (add correlation ID support)
- Modified: `src/integrations/` (S3 Object Lock configuration)
- New: `src/utils/geoip.py` (MaxMind integration)
- Modified: all template loggers (add geolocation and correlation ID)

**Success criteria:**
- Multi-step attacks traceable via single correlation ID
- Logs tamper-proof with S3 Object Lock verification
- All events include geolocation data
- Backup log stream operational with < 5 second lag

---

## Phase 3: Anti-Fingerprinting & Resilience (P1)

### 3.1 Anti-Fingerprinting Measures

**Gap:** The honeypot currently uses static SSH banners and predictable response patterns. Tools like `honeypot-detector`, Shodan's honeypot probability score, and manual analysis can identify the honeypot.

**Implementation:**

Create `src/emulation/anti_fingerprint.py`:
- **Banner rotation:** Rotate SSH banner versions on rebuild, matching real-world distribution
- **Timing jitter:** Add Gaussian-distributed delays to all responses (configurable mean/stddev)
- **Protocol compliance:** Full SSH protocol implementation (not just auth phase)
- **Error authenticity:** Match exact error message format of emulated OS
- **TCP stack tuning:** Adjust TCP window size, TTL, and options to match target OS
- **TLS configuration:** Real certificates (Let's Encrypt), cipher suite matching target server
- **Behavioral consistency:** If claiming to be Ubuntu 22.04, all responses must be consistent with that OS

Create `tests/anti_fingerprint/`:
- Test suite that runs fingerprinting tools against the honeypot
- Verify Shodan honeypot probability score < 0.3
- Verify `ssh-audit` shows expected algorithms for claimed version
- Verify HTTP headers match claimed web server

**Affected files:**
- New: `src/emulation/anti_fingerprint.py`
- Modified: `templates/basic-ssh/honeypot.py` (use anti-fingerprint layer)
- Modified: `templates/fake-api/server.js` (response header normalization)
- New: `tests/anti_fingerprint/`

**Success criteria:**
- Shodan honeypot probability < 0.3
- ssh-audit reports consistent with claimed SSH version
- Manual pen-tester cannot identify as honeypot within first 10 minutes
- Automated honeypot detection tools score < 30% confidence

---

### 3.2 DDoS Protection & Resource Limits

**Gap:** Rate limiting exists per-IP but no global resource protection. A distributed attack from many IPs can still exhaust honeypot resources.

**Implementation:**

Enhance `src/ratelimit/`:
- **Global connection limits:** Maximum total concurrent connections (all IPs)
- **Global rate limit:** Maximum new connections per second (all IPs)
- **Connection queuing:** Accept overflow connections into a queue with timeout
- **Resource circuit breaker:** If CPU > 80% or memory > 90%, temporarily reject new connections
- **SYN flood protection:** TCP SYN cookies at OS level
- **Slow-read protection:** Minimum data rate per connection, terminate idle

Enhance container resource limits:
- CPU: 0.5 cores max per honeypot container
- Memory: 256MB max (configurable)
- PIDs: 100 max
- File descriptors: 1024 max
- Disk I/O: rate limited via cgroups v2

**Affected files:**
- Modified: `src/ratelimit/` (add global limits, circuit breaker)
- Modified: Docker configurations (cgroup limits)
- Modified: `deploy/` (OS-level tuning scripts)

**Success criteria:**
- Honeypot remains responsive under 10,000 concurrent connections
- CPU never exceeds limit for > 30 seconds
- Memory OOM never kills logging or alerting processes
- Graceful degradation under DDoS (reject cleanly, don't crash)

---

## Phase 4: Ecosystem Integration (P2)

### 4.1 SOAR Playbook Integration

**Gap:** Alerts go to Slack/Discord/PagerDuty but don't trigger automated incident response playbooks. Security teams must manually create firewall rules, update blocklists, and initiate investigations.

**Implementation:**

Create `src/integrations/soar/`:
- `cortex.py` - TheHive/Cortex SOAR integration
- `phantom.py` - Splunk SOAR (Phantom) integration
- `xsoar.py` - Palo Alto XSOAR integration
- `generic_webhook.py` - Generic SOAR webhook with configurable payload templates

Automated response playbooks:
- **Blocklist feed:** Publish confirmed attacker IPs to firewall/IDS via API
- **IoC distribution:** Push indicators to production IDS/IPS rule sets
- **Ticket creation:** Auto-create investigation tickets in SOAR
- **Enrichment request:** Trigger deeper analysis of advanced attackers

Create `src/feeds/blocklist.py`:
- HTTP endpoint serving IP blocklist in standard formats
- Formats: plain text, CSV, STIX 2.1, TAXII
- Configurable confidence threshold for inclusion
- TTL per entry (auto-expire after configurable period)
- Allowlist support (exclude known researchers/scanners)

**Affected files:**
- New: `src/integrations/soar/` package
- New: `src/feeds/blocklist.py`
- Modified: `src/alerts/dispatcher.py` (add SOAR webhook type)

**Success criteria:**
- Confirmed attacker IPs appear in blocklist feed within 60 seconds
- SOAR playbook triggers within 30 seconds of critical alert
- Blocklist feed serves requests with < 100ms latency
- False positive rate in blocklist < 1%

---

### 4.2 STIX/TAXII Threat Intelligence Sharing

**Gap:** The architecture doc mentions STIX/TAXII and MISP export but no implementation exists. Honeypot intelligence stays siloed.

**Implementation:**

Create `src/feeds/stix.py`:
- Generate STIX 2.1 bundles from honeypot events
- Object types: `indicator`, `observed-data`, `attack-pattern`, `malware`, `threat-actor`
- Relationship mapping between objects
- Confidence scoring based on enrichment data

Create `src/feeds/taxii_server.py`:
- TAXII 2.1 server endpoint for automated sharing
- Collection management (per-template, per-severity)
- Authentication via API key
- Pagination for large result sets

Create `src/feeds/misp.py`:
- Push events to MISP instance
- Map honeypot events to MISP event format
- Attribute tagging (IP, domain, hash, URL)
- Galaxy/cluster assignment

**Affected files:**
- New: `src/feeds/` package
- Modified: `src/cli/main.py` (add `honeyclaw feeds` command group)

**Success criteria:**
- STIX bundles validate against STIX 2.1 schema
- TAXII server passes TAXII compliance tests
- MISP events appear correctly in target instance
- Automated sharing operational within 5 minutes of event

---

### 4.3 Malware Analysis Pipeline

**Gap:** File uploads and payloads captured by the honeypot aren't analyzed. Malware samples sit in logs without extraction, classification, or IoC generation.

**Implementation:**

Create `src/analysis/malware_pipeline.py`:
- **Extraction:** Identify and extract binary payloads from:
  - wget/curl downloads intercepted in SSH sessions
  - File uploads via API endpoints
  - Base64-encoded payloads in command parameters
  - Encoded/packed scripts
- **Static analysis:**
  - File type identification (magic bytes)
  - Hash generation (MD5, SHA1, SHA256)
  - String extraction
  - YARA rule matching
  - Packer detection
- **Sandbox integration:**
  - Submit to Cuckoo Sandbox API
  - Submit to ANY.RUN API
  - Submit to VirusTotal for scanning
  - Collect behavioral reports
- **IoC extraction:**
  - C2 domains/IPs from sandbox reports
  - Dropped file hashes
  - Registry modifications
  - Network indicators
- **Classification:**
  - Malware family identification
  - MITRE ATT&CK technique mapping from behavior
  - Threat actor attribution when possible

Create `src/analysis/yara_rules/`:
- Bundled YARA rules for common malware families
- Crypto miner detection
- Botnet client detection
- RAT detection
- Webshell detection

**Affected files:**
- New: `src/analysis/malware_pipeline.py`, `src/analysis/yara_rules/`
- Modified: `src/replay/recorder.py` (flag sessions with file transfers)
- Modified: `templates/fake-api/server.js` (extract upload payloads)

**Success criteria:**
- All binary payloads automatically extracted and hashed
- YARA rules detect 80%+ of known malware families
- Sandbox integration returns behavioral report within 10 minutes
- IoCs auto-published to threat feeds

---

## Phase 5: Advanced Capabilities (P2)

### 5.1 Kubernetes Orchestration

**Gap:** Deployment is manual Docker containers or Fly.io. No auto-scaling, no automated pod rotation, no service mesh.

**Implementation:**

Create `deploy/kubernetes/helm/honeyclaw/`:
- Helm chart with values for each template type
- `Deployment` manifests with:
  - Pod anti-affinity (spread across nodes)
  - Resource requests/limits
  - Liveness and readiness probes
  - Pod Security Standards (restricted)
- `NetworkPolicy` manifests:
  - Default deny all
  - Allow ingress from load balancer only
  - Allow egress only to logging service
- `CronJob` for automated pod rotation (24h default)
- `HorizontalPodAutoscaler`:
  - Scale based on connection count
  - Min 1, max configurable per region
- `ServiceMonitor` for Prometheus metrics export

Create `deploy/kubernetes/manifests/`:
- Raw manifests for non-Helm deployments
- Kustomize overlays for dev/staging/production

**Affected files:**
- New: `deploy/kubernetes/` (all manifests)
- Modified: Docker images (add health check endpoints)

**Success criteria:**
- `helm install honeyclaw` deploys full stack
- Auto-scaling responds to traffic within 60 seconds
- Pod rotation completes with zero dropped connections
- NetworkPolicy blocks all unauthorized traffic

---

### 5.2 Multi-Protocol Expansion

**Gap:** Current templates cover SSH, HTTP/REST, and enterprise services (RDP, LDAP, Samba, WinRM). Missing coverage for increasingly targeted services: Redis, MongoDB, Elasticsearch, Docker API, Kubernetes API.

**Implementation:**

Create new templates:
- `templates/nosql-trap/`:
  - Redis (port 6379) - Accept commands, log queries, return fake data
  - MongoDB (port 27017) - Accept connections, log queries
  - Elasticsearch (port 9200) - Fake cluster, log search queries
- `templates/container-trap/`:
  - Docker API (port 2375) - Fake Docker daemon, log container operations
  - Kubernetes API (port 6443) - Fake kube-apiserver, log kubectl commands
- `templates/database-trap/`:
  - MySQL (port 3306) - Accept auth, log queries
  - PostgreSQL (port 5432) - Accept auth, log queries
  - MSSQL (port 1433) - Accept auth, log queries

Each template includes:
- Protocol-accurate service emulation
- Credential capture
- Query/command logging
- Canary data seeding
- Alert rule integration

**Affected files:**
- New: `templates/nosql-trap/`, `templates/container-trap/`, `templates/database-trap/`
- Modified: `src/alerts/rules.py` (add protocol-specific rules)
- Modified: `src/cli/main.py` (register new templates)

**Success criteria:**
- Each service passes basic client connectivity test
- Nmap service detection identifies correct service
- All queries/commands logged with full payloads
- Canary data returned for sensitive queries

---

### 5.3 Performance Metrics & Dashboard

**Gap:** No centralized metrics on honeypot performance, attack volume, or intelligence quality.

**Implementation:**

Create `src/metrics/collector.py`:
- **Operational metrics:**
  - Connections per minute/hour/day (per template, per region)
  - Unique attacker IPs per day
  - Average attacker dwell time
  - Service uptime percentage
  - Log ingestion rate
  - Alert volume by severity
- **Intelligence metrics:**
  - Zero-day exploit candidates discovered
  - Malware samples collected
  - Unique credentials captured
  - New IoCs generated per day
  - Threat feed subscriber count
- **Quality metrics:**
  - Anti-fingerprinting score (periodic self-test)
  - False positive rate in alerts
  - Enrichment coverage (% of IPs enriched)
  - MITRE ATT&CK coverage (techniques observed)

Create `src/metrics/exporter.py`:
- Prometheus metrics endpoint (`/metrics`)
- StatsD push for legacy systems
- JSON API for custom dashboards

Grafana dashboard templates (`deploy/grafana/`):
- Attack overview dashboard
- Per-region breakdown
- Attacker profiling dashboard
- Intelligence quality scorecard

**Affected files:**
- New: `src/metrics/` package, `deploy/grafana/`
- Modified: all template entrypoints (instrument with metrics)

**Success criteria:**
- All operational metrics collected with < 1 second granularity
- Grafana dashboard renders within 3 seconds
- Historical data retained for 90+ days
- Metric gaps (missing data) < 0.1%

---

## Phase 6: Compliance & Testing (P2)

### 6.1 Automated Compliance

**Gap:** Legal docs (privacy policy, ToS, legality disclaimer) exist but compliance isn't automated. GDPR requires IP anonymization after retention period; this is documented but not enforced programmatically.

**Implementation:**

Create `src/compliance/retention.py`:
- Scheduled job to enforce retention policy:
  - Raw logs: hash IP addresses after 90 days
  - Anonymize any captured PII (email addresses in credentials)
  - Delete raw data after retention period
  - Preserve aggregated statistics indefinitely
- Audit log of all anonymization actions
- GDPR data subject access request handler (search by IP)

Create `src/compliance/audit.py`:
- Continuous audit of data handling practices
- Verify no real PII in canary data
- Verify no production credentials in honeypot configs
- Verify data retention policies are being enforced
- Generate compliance reports (PDF/JSON)

**Affected files:**
- New: `src/compliance/` package
- Modified: `src/cli/main.py` (add `honeyclaw compliance` commands)

**Success criteria:**
- IP anonymization runs automatically at 90-day mark
- DSAR response possible within 72 hours
- Compliance audit passes with zero violations
- Audit trail immutable and complete

---

### 6.2 Comprehensive Testing Suite

**Gap:** Tests exist for individual modules (alerts, canary, replay, escape detection) but no integration tests, no load tests, and no anti-detection validation.

**Implementation:**

Create `tests/integration/`:
- **End-to-end flow tests:**
  - Deploy honeypot -> connect as attacker -> verify logs -> verify alerts -> verify enrichment
  - Multi-step attack chain -> verify correlation IDs link events
  - Canary token trigger -> verify alert pipeline fires
- **SIEM integration tests:**
  - Verify events appear in Splunk/Elastic/Sentinel test instances
  - Verify SIEM detection rules fire correctly
- **Mesh tests:**
  - Multi-node deployment -> verify cross-node correlation
  - Node failure -> verify mesh continues functioning

Create `tests/load/`:
- **Connection flood:** 10,000 concurrent connections
- **Brute force simulation:** 1,000 auth attempts/minute
- **API abuse:** 10,000 requests/minute to fake API
- **Resource exhaustion:** Verify limits hold under pressure

Create `tests/anti_fingerprint/`:
- **Shodan scan:** Run against honeypot, verify low detection score
- **ssh-audit:** Verify protocol compliance
- **HTTP fingerprinting:** Verify headers match claimed server
- **Timing analysis:** Verify no statistical timing anomalies

Create `tests/security/`:
- **Container escape test:** Attempt known escape techniques, verify blocked
- **Log injection test:** Attempt to inject malicious log entries
- **Privilege escalation test:** Attempt to escalate within container
- **Network isolation test:** Attempt outbound connections, verify blocked

**Affected files:**
- New: `tests/integration/`, `tests/load/`, `tests/anti_fingerprint/`, `tests/security/`
- Modified: CI/CD pipeline (add test stages)

**Success criteria:**
- Integration tests cover all critical paths
- Load tests validate performance under 10x expected traffic
- Anti-fingerprint tests run in CI and block deploys that regress
- Security tests pass on every build

---

## Implementation Roadmap

### Phase 1: Critical Security & Reliability (Weeks 1-2)
| Task | Priority | Effort | Dependencies |
|---|---|---|---|
| 1.1 Health monitoring & compromise detection | P0 | Medium | None |
| 1.2 Infrastructure-as-Code (Terraform + Helm) | P0 | High | None |
| 1.3 Network isolation enforcement (AppArmor, Seccomp) | P0 | Medium | 1.2 |

### Phase 2: Enhanced Intelligence (Weeks 3-4)
| Task | Priority | Effort | Dependencies |
|---|---|---|---|
| 2.1 Stateful shell emulation & fake filesystem | P1 | High | None |
| 2.2 AI adaptive deception (sophistication classifier) | P1 | High | 2.1 |
| 2.3 MITRE ATT&CK full event mapping | P1 | Medium | None |
| 2.4 Correlation IDs + log immutability | P1 | Medium | ✅ DONE |

### Phase 3: Anti-Fingerprinting (Weeks 5-6)
| Task | Priority | Effort | Dependencies |
|---|---|---|---|
| 3.1 Anti-fingerprinting measures | P1 | High | 2.1 |
| 3.2 DDoS protection & resource limits | P1 | Medium | 1.2 |

### Phase 4: Ecosystem Integration (Weeks 7-8)
| Task | Priority | Effort | Dependencies |
|---|---|---|---|
| 4.1 SOAR playbook integration | P2 | Medium | None |
| 4.2 STIX/TAXII + MISP sharing | P2 | Medium | 2.3 |
| 4.3 Malware analysis pipeline | P2 | High | None |

### Phase 5: Advanced Capabilities (Weeks 9-10)
| Task | Priority | Effort | Dependencies |
|---|---|---|---|
| 5.1 Kubernetes orchestration (Helm chart) | P2 | High | 1.2 |
| 5.2 Multi-protocol expansion (Redis, MongoDB, k8s API) | P2 | High | 2.1 |
| 5.3 Performance metrics & Grafana dashboards | P2 | Medium | None |

### Phase 6: Compliance & Testing (Weeks 11-12)
| Task | Priority | Effort | Dependencies |
|---|---|---|---|
| 6.1 Automated compliance (GDPR retention, audits) | P2 | Medium | None |
| 6.2 Comprehensive testing suite | P2 | High | All above |

---

## Key Metrics to Track Post-Implementation

| Metric | Current | Target | Measurement |
|---|---|---|---|
| Mean time to detect compromise | Unknown | < 5 min | Health monitor logs |
| Attacker dwell time | ~30 sec | > 5 min | Session replay data |
| Anti-fingerprint score | Untested | < 0.3 (Shodan) | Periodic scan |
| MITRE ATT&CK coverage | Partial | 95%+ events tagged | Log analysis |
| False positive alert rate | Unknown | < 5% | SOC feedback loop |
| Log integrity | Not verified | 100% immutable | S3 Object Lock audit |
| Rebuild cycle time | Manual | < 5 min automated | IaC pipeline metrics |
| Unique IoCs/day | Not tracked | Tracked & published | Feed subscriber metrics |
| Integration test pass rate | N/A | 100% on deploy | CI/CD pipeline |
| Zero-day candidates/month | Not tracked | Tracked & triaged | Analysis pipeline |

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Honeypot compromise becomes attack platform | Medium | Critical | Egress blocking, 24h rebuild, health monitoring |
| Attacker fingerprints honeypot quickly | High | High | Anti-fingerprinting suite, timing jitter |
| Log data lost or tampered | Low | Critical | S3 Object Lock, backup stream, immutability |
| DDoS exhausts honeypot resources | Medium | Medium | Global rate limits, circuit breaker, k8s auto-scale |
| Real data leaks into honeypot | Low | Critical | Compliance audit, canary-only policy, automated checks |
| GDPR violation from IP retention | Medium | High | Automated anonymization at 90 days, audit trail |

---

*This plan transforms HoneyClaw from a capable honeypot framework into a production-grade threat intelligence platform. Each phase builds on the previous, with Phase 1 addressing critical security gaps that must be resolved before deploying in sensitive environments.*
