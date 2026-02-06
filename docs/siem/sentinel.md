# Azure Sentinel Integration Setup

This guide covers setting up Honeyclaw with Microsoft Azure Sentinel via the Log Analytics Data Collector API.

## Prerequisites

- Azure subscription with Sentinel enabled
- Log Analytics workspace
- Network connectivity from honeypots to Azure (HTTPS)

## Step 1: Create Log Analytics Workspace

If you don't have one:

1. Go to **Azure Portal > Create a resource**
2. Search for "Log Analytics workspace"
3. Click **Create**
4. Configure:
   - **Subscription**: Your subscription
   - **Resource group**: Create or select
   - **Name**: `honeyclaw-workspace`
   - **Region**: Select appropriate region
5. Click **Review + Create** then **Create**

## Step 2: Get Workspace Credentials

1. Go to your Log Analytics workspace
2. Navigate to **Settings > Agents management**
3. Copy:
   - **Workspace ID** (GUID format)
   - **Primary key** (base64 encoded)

## Step 3: Enable Microsoft Sentinel

1. Go to **Azure Portal > Microsoft Sentinel**
2. Click **Add**
3. Select your Log Analytics workspace
4. Click **Add**

## Step 4: Configure Honeyclaw

Create `/etc/honeyclaw/siem.yaml`:

```yaml
siem:
  provider: sentinel
  workspace_id: ${AZURE_WORKSPACE_ID}
  shared_key: ${AZURE_SHARED_KEY}
  log_type: HoneyclawEvents
  verify_ssl: true
  batch_size: 100
  flush_interval_seconds: 10
```

Set environment variables:

```bash
export AZURE_WORKSPACE_ID=your-workspace-id-guid
export AZURE_SHARED_KEY=your-primary-key-base64
```

## Step 5: Deploy Honeypot

```bash
./deploy-honeypot.sh --template basic-ssh --name prod-ssh --siem /etc/honeyclaw/siem.yaml
```

## Step 6: Verify Data Ingestion

After deployment, verify events are arriving:

1. Go to **Log Analytics workspace > Logs**
2. Run query:

```kql
HoneyclawEvents_CL
| take 10
```

> **Note**: Custom logs may take 5-20 minutes to appear initially. The table name will be `HoneyclawEvents_CL` (with `_CL` suffix for custom logs).

## Step 7: Import Analytics Rules

### Via Azure Portal

1. Go to **Microsoft Sentinel > Analytics**
2. Click **Create > Import**
3. Upload rules from `siem-rules/sentinel/analytic_rules.json`

### Via ARM Template

Deploy the rules using Azure CLI:

```bash
# Convert JSON to ARM template format if needed
az sentinel alert-rule create \
  --resource-group your-rg \
  --workspace-name honeyclaw-workspace \
  --rule-name "Honeyclaw-BruteForce" \
  --template @rule.json
```

### Key Analytics Rules

| Rule | Severity | Description |
|------|----------|-------------|
| Honeyclaw - Successful Honeypot Authentication | High | Any successful auth = compromise |
| Honeyclaw - Command Execution | High | Post-exploitation activity |
| Honeyclaw - Brute Force Attack | High | >10 failures in 5 min |
| Honeyclaw - Multi-Honeypot Attack | High | Same IP targeting multiple honeypots |

## Step 8: Create Workbook

1. Go to **Microsoft Sentinel > Workbooks**
2. Click **Add workbook**
3. Add visualizations:

### Sample KQL Queries

**Events Over Time**
```kql
HoneyclawEvents_CL
| summarize Count = count() by EventType_s, bin(TimeGenerated, 1h)
| render timechart
```

**Top Attacking IPs**
```kql
HoneyclawEvents_CL
| summarize EventCount = count() by SrcIpAddr_s
| top 10 by EventCount
| render piechart
```

**Critical Events Table**
```kql
HoneyclawEvents_CL
| where EventSeverity_s in ("High", "Critical")
| project TimeGenerated, SrcIpAddr_s, HoneypotId_s, EventType_s, EventMessage_s
| order by TimeGenerated desc
| take 100
```

**Geographic Distribution**
```kql
HoneyclawEvents_CL
| where isnotempty(SrcGeoCountry_s)
| summarize Count = count() by SrcGeoCountry_s
| render piechart
```

## ASIM Field Mappings

Honeyclaw maps to Azure Sentinel Information Model (ASIM):

| Honeyclaw | ASIM Field |
|-----------|------------|
| `timestamp` | `TimeGenerated` |
| `source_ip` | `SrcIpAddr` |
| `source_port` | `SrcPortNumber` |
| `destination_port` | `DstPortNumber` |
| `username` | `TargetUsername` |
| `event_type` | `EventType` |
| `command` | `CommandLine` |
| `honeypot_id` | Custom: `HoneypotId` |

## Step 9: Configure Automation

### Create Playbook for Incident Response

1. Go to **Microsoft Sentinel > Automation**
2. Click **Create > Playbook**
3. Configure Logic App workflow:
   - Trigger: "When Azure Sentinel incident is created"
   - Actions: Send email, Teams notification, block IP, etc.

Example automation:
- Send Teams alert for successful auth
- Create ServiceNow ticket for critical events
- Add attacker IP to Azure Firewall block list

## Testing

### Verify Workspace Connectivity

```bash
# Calculate signature (Python example in connector)
curl -X POST \
  "https://${WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01" \
  -H "Content-Type: application/json" \
  -H "Authorization: SharedKey ${WORKSPACE_ID}:${SIGNATURE}" \
  -H "Log-Type: HoneyclawTest" \
  -H "x-ms-date: ${RFC1123_DATE}" \
  -d '[{"test": "connectivity"}]'
```

### Check for Ingestion Errors

```kql
// Check ingestion health
_LogOperation
| where Category == "Ingestion"
| where TimeGenerated > ago(1h)
| where Detail contains "Honeyclaw"
```

## Troubleshooting

### "Invalid Shared Key" Error

- Verify Workspace ID is correct (GUID format)
- Ensure Shared Key is the full base64 string
- Check for trailing whitespace in credentials

### Events Not Appearing

1. Wait 5-20 minutes for initial ingestion
2. Check Log Analytics workspace for `_LogOperation` errors
3. Verify table name: `HoneyclawEvents_CL` (with `_CL` suffix)

### Signature Calculation Issues

The connector handles signature calculation automatically. If debugging manually:

```python
# Signature must be: Base64(HMAC-SHA256(decoded_key, string_to_sign))
# string_to_sign format:
# POST\n{content_length}\napplication/json\nx-ms-date:{rfc1123_date}\n/api/logs
```

## Cost Optimization

- Log Analytics charges per GB ingested
- Consider retention settings
- Use Data Collection Rules for filtering if high volume

## Permissions

Required Azure RBAC roles:
- **Log Analytics Contributor**: Write events
- **Microsoft Sentinel Contributor**: Manage rules (for setup)
