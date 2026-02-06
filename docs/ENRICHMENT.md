# Threat Intelligence Enrichment

Honeyclaw can automatically enrich attacker IPs with threat intelligence from multiple providers.

## Quick Start

```bash
# Install dependencies
pip install aiohttp pyyaml

# Set your API key (get free one from https://www.abuseipdb.com/account/api)
export ABUSEIPDB_API_KEY="your-api-key"

# Enrich an IP
python -m honeyclaw.src.enrichment.cli 185.220.101.1
```

## Configuration

Add to `honeyclaw.yaml`:

```yaml
enrichment:
  enabled: true
  providers:
    - abuseipdb    # Free: 1000 queries/day
    - greynoise    # Free: Community API (no key required)
    # - shodan     # Optional: Free tier limited
    # - virustotal # Optional: 500 queries/day
  cache_ttl: 3600  # Cache results for 1 hour
  cache_dir: ~/.honeyclaw/cache/enrichment  # Persistent cache (optional)
```

## Providers

### AbuseIPDB (Recommended - Free Tier)

**Free tier:** 1,000 queries/day

1. Sign up at https://www.abuseipdb.com/register
2. Get your API key from https://www.abuseipdb.com/account/api
3. Set environment variable:
   ```bash
   export ABUSEIPDB_API_KEY="your-key-here"
   ```

**Returns:**
- Abuse confidence score (0-100%)
- Total reports from users
- Attack categories (brute force, scanning, etc.)
- Country and ISP information

### GreyNoise (Free - No Key Required)

**Free tier:** Community API with rate limiting (no hard cap)

The Community API works without an API key. For higher limits, register at https://viz.greynoise.io/.

Optional: For enterprise features, set:
```bash
export GREYNOISE_API_KEY="your-key-here"
```

**Returns:**
- Classification: benign, malicious, or unknown
- Whether IP is "internet noise" (mass scanning)
- RIOT (Rule It Out) flag for known benign services
- Actor identification for known threat actors

### Shodan (Optional)

**Free tier:** 100 queries/day with account

1. Sign up at https://account.shodan.io/register
2. Get API key from https://account.shodan.io
3. Set environment variable:
   ```bash
   export SHODAN_API_KEY="your-key-here"
   ```

**Returns:**
- Open ports and services
- Known vulnerabilities (CVEs)
- Hostnames and banners
- Operating system detection

### VirusTotal (Optional)

**Free tier:** 500 queries/day, 4/minute

1. Sign up at https://www.virustotal.com/gui/join-us
2. Get API key from your profile
3. Set environment variable:
   ```bash
   export VIRUSTOTAL_API_KEY="your-key-here"
   ```

**Returns:**
- Detection results from 70+ security vendors
- Community reputation score
- Historical malicious activity

## CLI Usage

```bash
# Basic lookup
honeyclaw-enrich 185.220.101.1

# Use specific providers
honeyclaw-enrich 185.220.101.1 --providers abuseipdb,greynoise

# JSON output
honeyclaw-enrich 185.220.101.1 --json

# Skip cache (force fresh lookup)
honeyclaw-enrich 185.220.101.1 --skip-cache

# Check provider status
honeyclaw-enrich status

# View cache statistics
honeyclaw-enrich cache-stats
```

## Programmatic Usage

```python
import asyncio
from honeyclaw.src.enrichment import enrich_ip, get_engine

# Quick lookup
async def main():
    result = await enrich_ip("185.220.101.1")
    print(f"Verdict: {result['summary']['verdict']}")
    print(f"Risk Score: {result['summary']['risk_score']}")

asyncio.run(main())

# Or synchronous
from honeyclaw.src.enrichment.engine import enrich_ip_sync
result = enrich_ip_sync("185.220.101.1")
```

## Integrating with Honeypot Logs

To automatically enrich IPs in your honeypot logs, modify the `log_event` function:

```python
from honeyclaw.src.enrichment import enrich_ip
import asyncio

async def log_event_with_enrichment(event_type, data):
    """Log event with threat intel enrichment"""
    if 'ip' in data:
        # Run enrichment asynchronously
        enrichment = await enrich_ip(data['ip'])
        data['enrichment'] = enrichment.get('summary', {})
        data['enrichment_categories'] = enrichment.get('categories', [])
    
    # Log as normal
    log_event(event_type, data)
```

## Response Format

```json
{
  "ip": "185.220.101.1",
  "enriched": true,
  "timestamp": "2026-02-06T09:00:00Z",
  "summary": {
    "verdict": "malicious",
    "confidence": 0.85,
    "risk_score": 90,
    "malicious_verdicts": 2,
    "benign_verdicts": 0,
    "unknown_verdicts": 0
  },
  "categories": ["scanner", "brute_force", "ssh"],
  "tags": ["confidence:95%", "reports:127", "actor:known_scanner"],
  "providers": {
    "abuseipdb": {
      "provider": "abuseipdb",
      "success": true,
      "is_malicious": true,
      "confidence": 0.95,
      "risk_score": 95,
      "country": "DE",
      "report_count": 127
    },
    "greynoise": {
      "provider": "greynoise",
      "success": true,
      "is_malicious": true,
      "categories": ["scanner", "malicious"]
    }
  }
}
```

## Caching

Results are cached to avoid hitting rate limits:

- **Default TTL:** 3600 seconds (1 hour)
- **In-memory:** Default, lost on restart
- **Persistent:** Set `cache_dir` for file-based persistence

Tune the TTL based on your needs:
- Lower TTL (300s) for rapidly changing threat landscape
- Higher TTL (86400s) for stable known-bad IPs

## Best Practices

1. **Start with free providers** - AbuseIPDB + GreyNoise gives excellent coverage
2. **Enable caching** - Reduces API calls and improves response time
3. **Set rate limits** - Add delays between enrichments if processing many IPs
4. **Handle errors gracefully** - Some lookups will fail; don't block on enrichment
5. **Enrich asynchronously** - Don't block honeypot responses on enrichment lookups

## Troubleshooting

### "API key not configured"
Set the appropriate environment variable for the provider.

### "Rate limit exceeded"
- Wait for your rate limit to reset (usually 24 hours for daily limits)
- Enable caching to reduce duplicate lookups
- Use fewer providers or prioritize free-tier ones

### "Cannot look up private IP addresses"
Private/RFC1918 IPs (10.x.x.x, 192.168.x.x, etc.) are not indexed by threat intel providers.

### Empty results from GreyNoise
The IP may not have been observed scanning the internet. This is actually useful - it means the attacker is not a known mass scanner.
