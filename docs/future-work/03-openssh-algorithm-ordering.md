# Match OpenSSH Algorithm Ordering (Medium)

**Priority:** Medium
**Effort:** Medium (requires protocol analysis)
**Depends on:** 01-fix-ssh-handshake.md

## Problem

asyncssh advertises SSH algorithms in a different order than real OpenSSH 8.9p1. Sophisticated attackers (and automated scanners like Shodan) compare algorithm ordering to identify honeypots. The server claims to be `OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` but its KEX init doesn't match.

## What Needs to Match

A real OpenSSH 8.9p1 server sends algorithms in this order during KEX_INIT:

### Key Exchange
```
curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,
ecdh-sha2-nistp384,ecdh-sha2-nistp521,
sntrup761x25519-sha512@openssh.com,
diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,
diffie-hellman-group18-sha512,diffie-hellman-group14-sha256
```

### Host Key
```
ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,
sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,
ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,
sk-ecdsa-sha2-nistp256@openssh.com,
rsa-sha2-512,rsa-sha2-256
```

### Ciphers
```
chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,
aes128-gcm@openssh.com,aes256-gcm@openssh.com
```

### MACs
```
umac-64-etm@openssh.com,umac-128-etm@openssh.com,
hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,
hmac-sha1-etm@openssh.com,umac-64@openssh.com,
umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1
```

## Implementation

asyncssh allows specifying algorithm preferences via `create_server()`:

```python
server = await asyncssh.create_server(
    HoneypotServer, '0.0.0.0', PORT,
    server_host_keys=[key],
    server_version=SSH_BANNER,
    kex_algs=['curve25519-sha256', 'curve25519-sha256@libssh.org', ...],
    encryption_algs=['chacha20-poly1305@openssh.com', 'aes128-ctr', ...],
    mac_algs=['umac-64-etm@openssh.com', ...],
    compression_algs=['none', 'zlib@openssh.com'],
)
```

## How to Capture the Baseline

1. Set up a real Ubuntu 22.04 VM with OpenSSH 8.9p1
2. Capture the KEX_INIT with: `ssh -vvv user@real-server 2>&1 | grep -A 50 "kex_init"`
3. Or use Wireshark to capture the SSH handshake
4. Or use `ssh-audit`: `ssh-audit real-server`

## Files to Modify

- `templates/basic-ssh/honeypot.py` -- Add algorithm ordering params to `create_server()`
- Optionally: create `templates/basic-ssh/openssh_profile.py` with algorithm lists per OpenSSH version

## Success Criteria

- `ssh-audit` output matches real OpenSSH 8.9p1
- Algorithm ordering in KEX_INIT is byte-identical to real server
- Shodan's honeypot detection score does not flag algorithm mismatch

## References

- `reviews/expert-1-offensive.md` -- Algorithm ordering concern
- `reviews/expert-4-deception.md` -- Fingerprinting vectors
- [ssh-audit tool](https://github.com/jtesta/ssh-audit)
