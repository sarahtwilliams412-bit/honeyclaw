# Configure Webhook Alerting (Medium)

**Priority:** Medium
**Effort:** Small (configuration, no code changes)
**Depends on:** Nothing

## Problem

The honeypot has full alerting infrastructure built in (`src/alerts/dispatcher.py`) but no webhook URL is configured. The startup log confirms:

```json
{"alerting_enabled": false}
```

Without alerting, credential captures and suspicious activity go unnoticed until someone manually checks the logs.

## What to Do

1. **Choose a webhook target.** The alerting system supports:
   - Slack (incoming webhook)
   - Discord (webhook URL)
   - PagerDuty (events API)
   - Generic HTTP webhook

2. **Set the Fly.io secrets:**
   ```bash
   fly secrets set -a honeyclaw-ssh \
     ALERT_WEBHOOK_URL="https://hooks.slack.com/services/T.../B.../..." \
     ALERT_SEVERITY_THRESHOLD="MEDIUM" \
     HONEYPOT_ID="honeyclaw-prod-sjc"
   ```

3. **Verify alerting is enabled** in the startup log:
   ```json
   {"alerting_enabled": true}
   ```

4. **Test with a manual SSH connection:**
   ```bash
   ssh -p 8022 test@<host>
   ```
   Verify an alert appears in your webhook target.

## Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `ALERT_WEBHOOK_URL` | Yes | Webhook endpoint URL | `https://hooks.slack.com/...` |
| `ALERT_SEVERITY_THRESHOLD` | No | Minimum severity to alert on (default: MEDIUM) | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `HONEYPOT_ID` | No | Identifier included in alerts | `honeyclaw-prod-sjc` |

## Optional: Alert Aggregation

The audit identified that high-traffic periods could produce excessive alerts. Consider:
- Setting `ALERT_SEVERITY_THRESHOLD=HIGH` to reduce noise
- Implementing deduplication in the webhook target (e.g., Slack workflow that groups by IP)
- Future code work: add deduplication in `src/alerts/dispatcher.py`

## Files to Modify

None (configuration only). If alert aggregation is desired:
- `src/alerts/dispatcher.py` -- Add deduplication logic

## References

- `test-results/logging.md` (L-04) -- Webhook not configured
- `reviews/expert-2-defensive.md` -- Alert quality recommendations
