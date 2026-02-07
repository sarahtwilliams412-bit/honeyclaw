# Fix SSH Handshake (Critical)

**Priority:** Critical -- blocks all credential capture
**Effort:** Medium (requires asyncssh debugging)
**Depends on:** Nothing
**Unlocks:** 05-rerun-input-validation.md

## Problem

The SSH honeypot accepts TCP connections but fails during key exchange. External clients see:

```
kex_exchange_identification: read: Connection reset by peer
```

The server never sends an SSH banner and never reaches the authentication phase. This means the honeypot's core purpose -- capturing credentials -- does not work.

## What Works

- TCP port 8022 is open and accepting connections
- Internal Fly.io connections (172.16.7.242) DO complete the handshake and reach auth
- The asyncssh `create_server()` call with `server_version=SSH_BANNER` is correct
- Rate limiting, logging, and input validation all function when the handshake succeeds

## Likely Causes

1. **Rate limiting closes connections before banner is sent.** The `connection_made()` callback calls `conn.close()` for rate-limited IPs. This happens after asyncssh has accepted the TCP connection but potentially before the SSH banner exchange completes. asyncssh may be sending the banner at a lower level, but closing the connection immediately could cause the client to see a reset.

2. **Key algorithm mismatch.** The server generates RSA-2048 only (now ed25519 after v1.5.0). If the client and server can't agree on key exchange algorithms, asyncssh may silently drop the connection.

3. **asyncssh version issue.** The Dockerfile installs whatever version `pip install asyncssh` resolves to. A version mismatch or bug could cause KEX failure.

## Debugging Steps

1. **Check asyncssh version:** Pin a known-good version in the Dockerfile and test.

2. **Add KEX debugging:** asyncssh supports debug logging. Add before `create_server`:
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   asyncssh.set_debug_level(2)
   ```

3. **Test rate limiting interaction:** Temporarily disable rate limiting (`RATELIMIT_ENABLED=false`) and test external connections to isolate whether rate limiting is the cause.

4. **Test with multiple key types:** Generate both ed25519 and RSA keys and pass both to `server_host_keys`:
   ```python
   keys = [
       asyncssh.generate_private_key('ssh-ed25519'),
       asyncssh.generate_private_key('ssh-rsa', 2048),
   ]
   server = await asyncssh.create_server(..., server_host_keys=keys)
   ```

5. **Test locally with verbose SSH client:**
   ```bash
   ssh -vvv -p 8022 -o StrictHostKeyChecking=no test@localhost
   ```

## Files to Modify

- `templates/basic-ssh/honeypot.py` -- Fix the handshake/KEX issue
- `templates/basic-ssh/Dockerfile` -- Pin asyncssh version if needed

## Success Criteria

- `ssh -p 8022 test@<host>` reaches a password prompt
- Banner `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` is sent on connect
- Credentials are logged in JSON format
- Connection stays alive for at least 60 seconds
- Functional tests F-01 through F-05 all pass

## References

- `test-results/functional.md` -- Detailed failure logs
- `test-results/evasion.md` -- Detection analysis
- [asyncssh server docs](https://asyncssh.readthedocs.io/en/latest/api.html#server)
