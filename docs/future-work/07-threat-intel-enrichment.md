# Threat Intelligence Enrichment (Medium)

**Priority:** Medium
**Effort:** Medium
**Depends on:** Nothing (GeoIP import path already fixed)

## Problem

The honeypot logs raw IP addresses without context. A SOC analyst reviewing logs has to manually look up each IP to determine:
- Is this a known attacker?
- What country/ASN is it from?
- Is it a Tor exit node?
- Is it a cloud provider (likely scanner)?

The `src/enrichment/` module exists with providers for VirusTotal, GreyNoise, Shodan, and AbuseIPDB, but none are configured or wired into the honeypot.

## What Exists

- `src/utils/geoip.py` -- GeoIP lookup (now importable after __init__.py fix)
- `src/enrichment/providers/` -- Provider integrations (VirusTotal, GreyNoise, Shodan, AbuseIPDB)
- `honeypot.py` -- `ENHANCED_LOGGING_ENABLED` flag controls enrichment

## What to Do

### Step 1: Enable GeoIP (No API Key Needed)

GeoIP falls back to a basic IP-range lookup when MaxMind isn't available. To get full coverage:

1. Download MaxMind GeoLite2 databases (free account required):
   - GeoLite2-City.mmdb
   - GeoLite2-ASN.mmdb

2. Add to the Docker image or mount as a volume:
   ```dockerfile
   COPY GeoLite2-City.mmdb /usr/share/GeoIP/
   COPY GeoLite2-ASN.mmdb /usr/share/GeoIP/
   RUN pip install --no-cache-dir geoip2
   ```

3. Set env vars if using non-default paths:
   ```bash
   fly secrets set -a honeyclaw-ssh \
     GEOIP_DB_PATH="/data/GeoLite2-City.mmdb"
   ```

### Step 2: Wire Enrichment Providers into Honeypot

The existing enrichment providers in `src/enrichment/` need to be called from the logging pipeline. Add to `log_event()` in `honeypot.py`:

```python
# After existing geo enrichment
if source_ip and ENRICHMENT_ENABLED:
    try:
        from src.enrichment import enrich_ip
        intel = enrich_ip(source_ip)
        event.update(intel)
    except Exception:
        pass
```

### Step 3: Configure API Keys

```bash
fly secrets set -a honeyclaw-ssh \
  ABUSEIPDB_API_KEY="..." \
  GREYNOISE_API_KEY="..." \
  VIRUSTOTAL_API_KEY="..."
```

### Rate Limiting Consideration

Enrichment APIs have rate limits. Cache results per IP and use async/non-blocking calls:
- AbuseIPDB: 1000 checks/day (free)
- GreyNoise: 50 queries/day (free community)
- VirusTotal: 500 queries/day (free)

Cache in memory (already done in `src/utils/geoip.py`'s `_LRUCache`) or on disk.

## Files to Modify

- `templates/basic-ssh/honeypot.py` -- Wire enrichment into `log_event()`
- `templates/basic-ssh/Dockerfile` -- Install `geoip2`, optionally bundle GeoLite2 DB
- `deploy/flyio/fly-basic-ssh.toml` -- Add enrichment env vars

## Success Criteria

- Every log event includes `geo_country`, `geo_asn` fields
- Known-bad IPs flagged with `threat_intel: {abuseipdb_score: 100}`
- Enrichment doesn't block the logging pipeline (async or cached)
- API rate limits are respected

## References

- `test-results/logging.md` (L-05) -- Correlation/enrichment not enabled
- `reviews/expert-2-defensive.md` -- GeoIP, threat intel recommendations
- `src/enrichment/` -- Existing provider code
- `src/utils/geoip.py` -- GeoIP module (451 lines, fully implemented)
