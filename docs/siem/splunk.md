# Splunk Integration Setup

This guide covers setting up Honeyclaw with Splunk using the HTTP Event Collector (HEC).

## Prerequisites

- Splunk Enterprise 7.0+ or Splunk Cloud
- HTTP Event Collector enabled
- Network connectivity from honeypots to Splunk HEC endpoint

## Step 1: Enable HTTP Event Collector

1. Log in to Splunk Web
2. Go to **Settings > Data Inputs > HTTP Event Collector**
3. Click **Global Settings**
4. Ensure **Enable SSL** is checked
5. Set **HTTP Port Number** (default: 8088)
6. Click **Save**

## Step 2: Create HEC Token

1. Go to **Settings > Data Inputs > HTTP Event Collector**
2. Click **New Token**
3. Configure:
   - **Name**: `honeyclaw`
   - **Source name override**: `honeyclaw`
   - **Description**: Honeyclaw honeypot events
4. Click **Next**
5. Select or create index:
   - **Index**: `honeypot` (create if needed)
6. Click **Review** then **Submit**
7. Copy the generated token

## Step 3: Create Honeypot Index

1. Go to **Settings > Indexes**
2. Click **New Index**
3. Configure:
   - **Index Name**: `honeypot`
   - **Max Size**: As needed (recommend 100GB+)
   - **Retention**: As needed (recommend 90+ days)
4. Click **Save**

## Step 4: Configure Honeyclaw

### Option A: Configuration File

Create `/etc/honeyclaw/siem.yaml`:

```yaml
siem:
  provider: splunk
  endpoint: https://splunk.example.com:8088
  token: ${SPLUNK_HEC_TOKEN}
  index: honeypot
  source: honeyclaw
  sourcetype: honeyclaw:events
  verify_ssl: true
  batch_size: 100
  flush_interval_seconds: 10
```

### Option B: Environment Variables

```bash
export HONEYCLAW_SIEM_PROVIDER=splunk
export HONEYCLAW_SIEM_ENDPOINT=https://splunk.example.com:8088
export HONEYCLAW_SIEM_TOKEN=your-hec-token-here
export SPLUNK_INDEX=honeypot
```

## Step 5: Deploy Honeypot with SIEM

```bash
# With config file
./deploy-honeypot.sh --template basic-ssh --name prod-ssh --siem /etc/honeyclaw/siem.yaml

# With environment variables
./deploy-honeypot.sh --template basic-ssh --name prod-ssh --siem splunk
```

## Step 6: Import Detection Rules

### Install Saved Searches

1. Open `siem-rules/splunk/honeyclaw_alerts.spl`
2. In Splunk Web, go to **Settings > Searches, reports, and alerts**
3. Click **New Search**
4. Copy each search from the file
5. Configure alert actions as needed

### Key Alerts

| Alert | Severity | Description |
|-------|----------|-------------|
| `honeyclaw_brute_force` | High | >10 auth failures from single IP in 5 min |
| `honeyclaw_successful_auth` | Critical | Any successful honeypot authentication |
| `honeyclaw_command_execution` | Critical | Command executed on honeypot |
| `honeyclaw_malicious_tools` | High | Known attack tool patterns detected |

## Step 7: Create Dashboard

### Basic Dashboard

```xml
<dashboard>
  <label>Honeyclaw Overview</label>
  <row>
    <panel>
      <chart>
        <title>Events Over Time</title>
        <search>
          <query>index=honeypot sourcetype="honeyclaw:events" | timechart count by event_type</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Top Attackers</title>
        <search>
          <query>index=honeypot sourcetype="honeyclaw:events" | stats count by src_ip | sort -count | head 10</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>
    <panel>
      <table>
        <title>Critical Events</title>
        <search>
          <query>index=honeypot sourcetype="honeyclaw:events" severity="critical" | table _time, src_ip, honeypot_id, event_type, user</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
```

## Field Mappings

Honeyclaw uses Splunk CIM (Common Information Model) compatible fields:

| Honeyclaw Field | Splunk CIM Field |
|-----------------|------------------|
| `source_ip` | `src_ip` |
| `source_port` | `src_port` |
| `destination_port` | `dest_port` |
| `username` | `user` |
| `protocol` | `transport` |
| `event_type` | `action` (mapped) |

## Testing

### Verify HEC Connectivity

```bash
curl -k https://splunk.example.com:8088/services/collector/health \
  -H "Authorization: Splunk YOUR-TOKEN"
```

### Send Test Event

```bash
curl -k https://splunk.example.com:8088/services/collector/event \
  -H "Authorization: Splunk YOUR-TOKEN" \
  -d '{"event": {"test": "honeyclaw connectivity"}, "index": "honeypot"}'
```

### Verify in Splunk

```
index=honeypot | head 10
```

## Troubleshooting

### "Invalid token" Error

- Verify token is correct
- Check token hasn't been disabled
- Ensure token has access to target index

### Events Not Appearing

1. Check HEC is enabled: `curl https://splunk:8088/services/collector/health`
2. Verify index exists and token has write access
3. Check for indexer queue delays
4. Review `_internal` logs for HEC errors

### SSL Certificate Issues

```yaml
# Development only - not for production!
siem:
  verify_ssl: false
```

For production, add CA certificate:

```yaml
siem:
  verify_ssl: true
  ca_cert_path: /etc/ssl/certs/splunk-ca.pem
```

## Performance Tuning

For high-volume honeypots (>1000 events/min):

```yaml
siem:
  batch_size: 500
  flush_interval_seconds: 5
  timeout_seconds: 60
```

Consider deploying Heavy Forwarders closer to honeypot infrastructure.
