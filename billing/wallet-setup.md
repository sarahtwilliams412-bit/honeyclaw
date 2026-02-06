# Wallet Setup Guide

## Overview

Honey Claw accepts payments on **Solana** in SOL and USDC. This document covers wallet setup for receiving payments.

---

## Payment Wallet

### Current Configuration
```
Network: Solana Mainnet
Address: [PLACEHOLDER - Sarah to provide]
Accepts: SOL, USDC (SPL)
```

> ⚠️ **Action Required:** Sarah needs to provide a Solana wallet address for payments.

---

## Recommended Wallet Setup

### Option A: Hardware Wallet (Recommended)
**Best for:** Maximum security, larger amounts

1. **Ledger Nano X/S Plus**
   - Install Solana app via Ledger Live
   - Connect to Phantom or Solflare as interface
   - Never expose seed phrase

2. **Setup Steps:**
   ```
   1. Initialize Ledger with new seed phrase
   2. Write seed phrase on metal backup (not paper)
   3. Install Solana app
   4. Connect to Phantom browser extension
   5. Use Ledger address as payment destination
   ```

### Option B: Phantom Wallet
**Best for:** Convenience, smaller amounts, quick setup

1. Install Phantom browser extension
2. Create new wallet (NOT import)
3. Backup seed phrase securely
4. Use this address for payments

### Option C: Multi-sig (Future)
**Best for:** Team treasury, large amounts

- Squads Protocol (Solana native multi-sig)
- Require 2/3 or 3/5 signatures
- Recommended for post-MVP treasury

---

## Wallet Address Checklist

Before publishing payment address:

- [ ] Wallet created fresh (not reused)
- [ ] Seed phrase backed up (offline, secure)
- [ ] Test transaction sent and received
- [ ] Address verified on Solscan
- [ ] USDC token account created (receive small amount first)

---

## Token Accounts

Solana requires token accounts for SPL tokens. Before receiving USDC:

```bash
# The wallet needs a USDC token account
# Created automatically when receiving first USDC
# Or manually via Phantom: Add Token → USDC

USDC Mint (Mainnet): EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
```

---

## Monitoring Payments

### Manual (MVP)
1. Bookmark Solscan address page:
   ```
   https://solscan.io/account/[WALLET_ADDRESS]
   ```
2. Check daily for incoming transactions
3. Cross-reference with `/verify` requests

### Automated (Future)
- Helius webhook: https://helius.dev
- Shyft webhook: https://shyft.to
- Custom bot integration

---

## Security Best Practices

### DO ✅
- Use hardware wallet for main treasury
- Keep seed phrase offline (metal backup)
- Use separate wallet for operations vs. treasury
- Regular withdrawals to cold storage
- Enable Phantom's transaction simulation

### DON'T ❌
- Share seed phrase with anyone
- Store seed phrase digitally (no photos, no cloud)
- Use same wallet for personal and business
- Leave large amounts in hot wallet
- Click suspicious transaction requests

---

## Withdrawal Procedure

Weekly (or when balance > $500):

1. Connect hardware wallet
2. Transfer to cold storage wallet
3. Leave small amount for gas
4. Log withdrawal in `payments.json`

---

## Emergency Procedures

### Wallet Compromised
1. DO NOT send more funds to compromised wallet
2. Update payment address everywhere immediately
3. Notify users of new address
4. Investigate how compromise occurred
5. Report to community if user funds affected

### Lost Access
1. Use seed phrase backup to restore
2. If seed phrase lost: funds are unrecoverable
3. This is why hardware wallet + metal backup is critical

---

## Address Publication

Once Sarah provides wallet address, update these locations:

- [ ] `PRICING.md` - Replace placeholder
- [ ] Discord bot payment command
- [ ] Website/landing page
- [ ] Twitter/marketing materials

---

## Quick Reference

| Item | Value |
|------|-------|
| Network | Solana Mainnet |
| Payment Wallet | `[PLACEHOLDER]` |
| USDC Mint | `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` |
| Explorer | https://solscan.io |
| Min Payment | $50 USD equivalent |

---

*Last updated: 2026-02-05*
