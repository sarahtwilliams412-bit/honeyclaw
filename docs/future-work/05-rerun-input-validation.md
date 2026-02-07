# Re-run Input Validation Tests (High)

**Priority:** High
**Effort:** Small (mostly re-running existing tests)
**Depends on:** 01-fix-ssh-handshake.md (must be fixed first)

## Problem

The 2026-02-07 security audit reported 55/55 input validation tests as "passing." This was misleading: 50 of 55 tests resulted in `Connection reset by peer` during key exchange, meaning the test payloads never reached the application-layer validation code. Only 5 null-byte tests (I-03) genuinely reached the validation layer and were properly handled via `SASLPrepError`.

The test script has been updated with proper outcome tracking (see `test-results/test_input_validation.py`), but the actual test results in `test-results/input-validation.md` still reflect the original run.

## What to Do

1. **Fix the SSH handshake first** (task 01). Tests are useless until auth works.

2. **Re-run the test suite** against the fixed honeypot:
   ```bash
   python test-results/test_input_validation.py <host> <port> -o test-results/input-validation.md
   ```

3. **Review the new results.** With a working SSH handshake, expect one of:
   - `OUTCOME_AUTH_REJECTED` -- payload reached validation, properly rejected (good)
   - `OUTCOME_APP_ERROR` -- payload triggered application-level error (acceptable)
   - `OUTCOME_CONN_RESET` -- still resetting (bad, needs further investigation)

4. **Update the audit report** (`SECURITY-AUDIT-2026-02-07.md`) with the corrected counts.

5. **Pay special attention to:**
   - I-01/I-02 (overflow): Do 65536-byte usernames/passwords crash the server?
   - I-05 (log injection): Do CRLF/newline payloads corrupt the JSON log?
   - I-06 (shell metacharacters): Does `$(sleep 5)` cause a timing delay?
   - I-07 (format strings): Does `%n%n%n` crash or leak memory?

## Files to Modify

- `test-results/input-validation.md` -- Replace with new test results
- `SECURITY-AUDIT-2026-02-07.md` -- Update input validation count and status
- `EXECUTION-LOG.md` -- Update Agent 3 results

## Success Criteria

- All 55 tests reach the validation layer (outcome is `auth_rejected` or `app_error`)
- Zero injection evidence across all tests
- Server remains available after all tests (no crashes)
- Report accurately reflects which tests passed at the validation layer
