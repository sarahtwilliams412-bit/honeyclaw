# Honeyclaw SIEM Detection Rules

Pre-built detection rules for enterprise SIEM platforms.

## Available Rules

### Splunk (`splunk/`)
- `honeyclaw_alerts.spl` - Saved searches and correlation rules

**Import**: Settings > Searches, reports, and alerts > New Search

### Elastic SIEM (`elastic/`)
- `detection_rules.ndjson` - Elastic Security detection rules

**Import**: Security > Rules > Import rules

### Azure Sentinel (`sentinel/`)
- `analytic_rules.json` - Analytics rules and hunting queries

**Import**: Microsoft Sentinel > Analytics > Import

### IBM QRadar (`qradar/`)
- `honeyclaw_rules.xml` - Custom rules and log source type

**Import**: Admin > Extensions Management > Add

## Detection Coverage

| Rule | MITRE Tactic | MITRE Technique | Severity |
|------|--------------|-----------------|----------|
| Brute Force Attack | Credential Access | T1110 | High |
| Successful Auth | Initial Access | T1078 | Critical |
| Command Execution | Execution | T1059 | Critical |
| Data Exfiltration | Exfiltration | T1041 | Critical |
| Port Scan | Discovery | T1046 | Medium |
| Exploit Attempt | Initial Access | T1190 | High |
| Multi-Honeypot Attack | Reconnaissance | T1595 | High |
| Credential Stuffing | Credential Access | T1110.004 | Medium |
| Lateral Movement | Lateral Movement | T1021 | High |
| Malware Detection | Execution | T1204 | Critical |

## Customization

All rules can be customized for your environment:

1. Adjust thresholds (e.g., brute force attempt count)
2. Modify time windows
3. Add custom fields or tags
4. Configure alert actions

## Updates

Rules are updated periodically. Check the repository for the latest versions.
