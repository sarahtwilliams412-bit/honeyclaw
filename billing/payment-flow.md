# Honey Claw Payment Flow

## Payment Provider: Stripe

### Setup Required
1. Stripe account (stripe.com)
2. API keys (publishable + secret)
3. Webhook endpoint for subscription events

### Products to Create in Stripe

| Product | Price ID | Amount |
|---------|----------|--------|
| Starter | price_starter | $1/month |
| Pro | price_pro | $25/month |
| Enterprise | price_enterprise | $99/month |

### Integration Flow

```
User clicks "Subscribe" 
    ↓
Redirect to Stripe Checkout
    ↓
User enters credit card
    ↓
Stripe processes payment
    ↓
Webhook: checkout.session.completed
    ↓
Provision honeypot access
    ↓
Send welcome email
```

### Webhook Events to Handle

- `checkout.session.completed` - New subscription, provision access
- `invoice.paid` - Renewal successful, maintain access
- `invoice.payment_failed` - Payment failed, send warning
- `customer.subscription.deleted` - Cancelled, revoke access

### Telegram Bot Integration

```
/subscribe → Generate Stripe checkout link → User pays → Webhook confirms → Bot grants access
```

### Environment Variables

```bash
STRIPE_SECRET_KEY=sk_live_...
STRIPE_PUBLISHABLE_KEY=pk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_STARTER_PRICE_ID=price_...
STRIPE_PRO_PRICE_ID=price_...
STRIPE_ENTERPRISE_PRICE_ID=price_...
```

### Code Location

- `/honeyclaw/src/stripe/checkout.js` - Create checkout sessions
- `/honeyclaw/src/stripe/webhook.js` - Handle Stripe events
- `/honeyclaw/src/stripe/customer.js` - Customer management

### Security

- Verify webhook signatures
- Use HTTPS only
- Never log full card numbers
- Store only Stripe customer IDs
