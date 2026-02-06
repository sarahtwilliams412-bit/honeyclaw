# Honey Claw Deployment Guide

## Production Environment

### Current Live Deployment

| Property | Value |
|----------|-------|
| **IP Address** | `149.248.202.23` |
| **Port** | `8022` |
| **App Name** | `honeyclaw-ssh` |
| **Platform** | Fly.io |
| **Region** | sjc (San Jose) |
| **Cost** | ~$2/month (dedicated IPv4) |

### Quick Test

```bash
# This will be logged by the honeypot!
ssh -p 8022 admin@149.248.202.23
```

---

## Fly.io Deployment

### Prerequisites

1. Fly.io account and CLI installed
2. Docker image ready for deployment

### Step 1: Create App

```bash
fly apps create honeyclaw-ssh
```

### Step 2: Deploy

```bash
fly deploy -a honeyclaw-ssh
```

### Step 3: Allocate Dedicated IPv4 (CRITICAL!)

⚠️ **This step is REQUIRED for TCP services!**

Fly.io's shared IPv4 addresses only route HTTP(S) traffic through their Anycast network. Raw TCP services like SSH **will not work** without a dedicated IPv4.

```bash
# Allocate dedicated IPv4 ($2/month)
fly ips allocate-v4 --yes -a honeyclaw-ssh

# Verify allocation
fly ips list -a honeyclaw-ssh
```

**Symptoms of missing dedicated IPv4:**
- SSH connections timeout
- `Connection refused` errors
- Works on IPv6 but not IPv4

### Step 4: Verify Deployment

```bash
# Check status
fly status -a honeyclaw-ssh

# View logs
fly logs -a honeyclaw-ssh

# SSH into machine (admin)
fly ssh console -a honeyclaw-ssh
```

---

## fly.toml Configuration

```toml
app = "honeyclaw-ssh"
primary_region = "sjc"

[build]
  image = "honeyclaw/basic-ssh:latest"

[[services]]
  internal_port = 22
  protocol = "tcp"

  [[services.ports]]
    port = 8022
    handlers = []
```

### Why Port 8022?

Fly.io reserves port 22 for its internal SSH proxy (`fly ssh console`). External SSH services must use alternate ports:

- **8022** - Common alternative (our choice)
- **2222** - Another common alternative
- **22022** - Easy to remember

---

## Common Issues & Solutions

### Issue: Connection Timeout on IPv4

**Symptom:** `ssh -p 8022 admin@149.248.202.23` times out

**Cause:** Missing dedicated IPv4 (shared IPs don't route TCP)

**Fix:**
```bash
fly ips allocate-v4 --yes -a honeyclaw-ssh
```

### Issue: Connection Works on IPv6 Only

**Symptom:** IPv6 connects but IPv4 doesn't

**Cause:** Same as above - shared IPv4 only handles HTTP(S)

**Fix:** Allocate dedicated IPv4

### Issue: "Address already in use" on Port 22

**Symptom:** Container fails to start, port conflict

**Cause:** Fly's internal SSH uses port 22

**Fix:** Use alternate port (8022) in fly.toml

### Issue: Logs Not Showing Connections

**Symptom:** Connections work but no log output

**Cause:** Logging misconfiguration or stdout buffering

**Fix:** Ensure honeypot logs to stdout unbuffered

---

## Monitoring

### Live Logs

```bash
# Stream logs
fly logs -a honeyclaw-ssh

# Last 100 lines
fly logs -a honeyclaw-ssh -n 100
```

### Health Check

```bash
# Quick connectivity test
nc -zv 149.248.202.23 8022

# Full SSH banner grab
echo "" | nc 149.248.202.23 8022
```

### Resource Usage

```bash
fly status -a honeyclaw-ssh
fly scale show -a honeyclaw-ssh
```

---

## Cost Breakdown

| Resource | Monthly Cost |
|----------|--------------|
| Fly.io Machine (shared-cpu-1x) | ~$3 |
| Dedicated IPv4 | $2 |
| **Total** | **~$5/month** |

---

## Security Considerations

1. **Isolation:** Honeypot runs in isolated Fly.io VM
2. **No Outbound:** Configure firewall to block outbound (except logs)
3. **Log Everything:** All connections should be logged
4. **Monitor Abuse:** Watch for cryptomining or botnet activity
5. **Rotate Regularly:** Consider periodic redeployment

---

## Changelog

- **2026-02-05:** Initial deployment with dedicated IPv4 (149.248.202.23)
- **2026-02-05:** Learned that Fly.io shared IPs don't route TCP properly
