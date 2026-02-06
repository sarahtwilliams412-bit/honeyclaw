# Elasticsearch / Elastic SIEM Integration Setup

This guide covers setting up Honeyclaw with Elasticsearch and Elastic Security (SIEM).

## Prerequisites

- Elasticsearch 7.10+ or Elastic Cloud
- Kibana with Elastic Security enabled
- Network connectivity from honeypots to Elasticsearch

## Step 1: Create API Key

### Option A: Kibana UI

1. Log in to Kibana
2. Go to **Stack Management > Security > API Keys**
3. Click **Create API key**
4. Configure:
   - **Name**: `honeyclaw`
   - **Role descriptors**: (see below)
5. Click **Create**
6. Copy the API key (shown only once)

### Option B: API

```bash
curl -X POST "https://elasticsearch:9200/_security/api_key" \
  -H "Content-Type: application/json" \
  -u elastic:password \
  -d '{
    "name": "honeyclaw",
    "role_descriptors": {
      "honeyclaw_writer": {
        "cluster": ["monitor"],
        "indices": [
          {
            "names": ["honeyclaw-*"],
            "privileges": ["create_index", "write", "read", "view_index_metadata"]
          }
        ]
      }
    }
  }'
```

## Step 2: Create Index Template

The connector can create this automatically, or manually:

```bash
curl -X PUT "https://elasticsearch:9200/_index_template/honeyclaw" \
  -H "Content-Type: application/json" \
  -u elastic:password \
  -d '{
    "index_patterns": ["honeyclaw-*"],
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 1
      },
      "mappings": {
        "properties": {
          "@timestamp": {"type": "date"},
          "message": {"type": "text"},
          "event": {
            "properties": {
              "kind": {"type": "keyword"},
              "category": {"type": "keyword"},
              "type": {"type": "keyword"},
              "action": {"type": "keyword"},
              "outcome": {"type": "keyword"},
              "severity": {"type": "integer"}
            }
          },
          "source": {
            "properties": {
              "ip": {"type": "ip"},
              "port": {"type": "integer"},
              "geo": {
                "properties": {
                  "country_iso_code": {"type": "keyword"},
                  "city_name": {"type": "keyword"}
                }
              }
            }
          },
          "observer": {
            "properties": {
              "name": {"type": "keyword"},
              "type": {"type": "keyword"}
            }
          },
          "honeyclaw": {
            "properties": {
              "honeypot_id": {"type": "keyword"},
              "honeypot_template": {"type": "keyword"},
              "service": {"type": "keyword"},
              "session_id": {"type": "keyword"}
            }
          }
        }
      }
    }
  }'
```

## Step 3: Configure Honeyclaw

### Configuration File

Create `/etc/honeyclaw/siem.yaml`:

```yaml
siem:
  provider: elastic
  endpoint: https://elasticsearch.example.com:9200
  api_key: ${ELASTIC_API_KEY}
  index: honeyclaw-events
  verify_ssl: true
  batch_size: 100
  flush_interval_seconds: 10
```

### Elastic Cloud

For Elastic Cloud deployments:

```yaml
siem:
  provider: elastic
  endpoint: https://deployment-id.es.us-west-1.aws.cloud.es.io:443
  api_key: ${ELASTIC_CLOUD_API_KEY}
  index: honeyclaw-events
```

## Step 4: Deploy Honeypot

```bash
export ELASTIC_API_KEY=your-api-key-here
./deploy-honeypot.sh --template basic-ssh --name prod-ssh --siem /etc/honeyclaw/siem.yaml
```

## Step 5: Import Detection Rules

### Import via Kibana API

```bash
# Export rules from this repo
cat siem-rules/elastic/detection_rules.ndjson | while read -r rule; do
  curl -X POST "https://kibana:5601/api/detection_engine/rules" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -u elastic:password \
    -d "$rule"
done
```

### Or via Kibana UI

1. Go to **Security > Rules > Detection rules**
2. Click **Import rules**
3. Upload `siem-rules/elastic/detection_rules.ndjson`

### Key Rules

| Rule | Risk Score | Description |
|------|------------|-------------|
| Successful Honeypot Authentication | 99 | Critical - immediate investigation |
| Command Execution on Honeypot | 95 | Active exploitation |
| Brute Force Attack Detected | 73 | Multiple auth failures |
| Port Scan Detected | 47 | Reconnaissance activity |

## Step 6: Create Index Pattern

1. Go to **Stack Management > Index Patterns**
2. Click **Create index pattern**
3. Pattern: `honeyclaw-*`
4. Time field: `@timestamp`
5. Click **Create**

## Step 7: Create Dashboard

Import or create a dashboard in Kibana:

```json
{
  "title": "Honeyclaw Overview",
  "panels": [
    {
      "type": "lens",
      "title": "Events Over Time",
      "attributes": {
        "visualizationType": "lnsXY"
      }
    },
    {
      "type": "lens", 
      "title": "Top Source IPs",
      "attributes": {
        "visualizationType": "lnsPie"
      }
    },
    {
      "type": "search",
      "title": "Critical Events",
      "attributes": {
        "columns": ["@timestamp", "source.ip", "observer.name", "event.action"]
      }
    }
  ]
}
```

## ECS Field Mappings

Honeyclaw uses Elastic Common Schema (ECS) for maximum compatibility:

| Honeyclaw | ECS Field |
|-----------|-----------|
| `timestamp` | `@timestamp` |
| `source_ip` | `source.ip` |
| `source_port` | `source.port` |
| `destination_port` | `destination.port` |
| `username` | `user.name` |
| `honeypot_id` | `observer.name` |
| `event_type` | `event.action` |
| `command` | `process.command_line` |
| `payload_hash` | `file.hash.sha256` |
| `geo_country` | `source.geo.country_iso_code` |

## Testing

### Verify Connectivity

```bash
curl -s "https://elasticsearch:9200" \
  -H "Authorization: ApiKey YOUR_API_KEY"
```

### Check Cluster Health

```bash
curl -s "https://elasticsearch:9200/_cluster/health" \
  -H "Authorization: ApiKey YOUR_API_KEY"
```

### Send Test Document

```bash
curl -X POST "https://elasticsearch:9200/honeyclaw-test/_doc" \
  -H "Content-Type: application/json" \
  -H "Authorization: ApiKey YOUR_API_KEY" \
  -d '{
    "@timestamp": "2024-01-15T10:30:00Z",
    "message": "Test event from Honeyclaw",
    "event": {"action": "test"}
  }'
```

### Verify in Kibana

Go to **Discover** and select `honeyclaw-*` index pattern.

## Troubleshooting

### Authentication Errors

- Verify API key format: `id:api_key` base64 encoded
- Check API key hasn't been invalidated
- Ensure key has write permissions to index

### Index Not Created

```bash
# Check if template exists
curl "https://elasticsearch:9200/_index_template/honeyclaw" \
  -H "Authorization: ApiKey YOUR_API_KEY"

# Create manually if needed (see Step 2)
```

### Mapping Conflicts

If field types conflict with existing data:

```bash
# Create new index with correct mappings
# Reindex existing data if needed
POST _reindex
{
  "source": {"index": "honeyclaw-old"},
  "dest": {"index": "honeyclaw-new"}
}
```

## Performance Tuning

### High-Volume Configuration

```yaml
siem:
  batch_size: 500
  flush_interval_seconds: 5
  timeout_seconds: 60
```

### Index Settings

For high-volume honeypots:

```json
{
  "settings": {
    "number_of_shards": 3,
    "refresh_interval": "30s",
    "translog": {
      "durability": "async",
      "sync_interval": "30s"
    }
  }
}
```

## Data Streams (Optional)

For time-series optimized storage:

```bash
# Create data stream template
PUT _index_template/honeyclaw-ds
{
  "index_patterns": ["honeyclaw-events"],
  "data_stream": {},
  "template": {
    "settings": {...},
    "mappings": {...}
  }
}
```
