const Stripe = require('stripe');

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const PRICE_IDS = {
  starter: process.env.STRIPE_STARTER_PRICE_ID,
  pro: process.env.STRIPE_PRO_PRICE_ID,
  enterprise: process.env.STRIPE_ENTERPRISE_PRICE_ID
};

const TIER_LIMITS = {
  starter: 1,
  pro: 5,
  enterprise: 999
};

/**
 * Create a Stripe Checkout session for subscription
 * @param {string} tier - 'starter', 'pro', or 'enterprise'
 * @param {string} telegramUserId - Telegram user ID for reference
 * @param {string} successUrl - Redirect URL on success
 * @param {string} cancelUrl - Redirect URL on cancel
 * @returns {Promise<{url: string, sessionId: string}>}
 */
async function createCheckoutSession(tier, telegramUserId, successUrl, cancelUrl) {
  if (!PRICE_IDS[tier]) {
    throw new Error(`Invalid tier: ${tier}`);
  }

  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    payment_method_types: ['card'],
    line_items: [
      {
        price: PRICE_IDS[tier],
        quantity: 1
      }
    ],
    success_url: successUrl || `${process.env.APP_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: cancelUrl || `${process.env.APP_URL}/cancel`,
    metadata: {
      telegram_user_id: telegramUserId,
      tier: tier,
      honeypot_limit: TIER_LIMITS[tier]
    },
    subscription_data: {
      metadata: {
        telegram_user_id: telegramUserId,
        tier: tier
      }
    }
  });

  return {
    url: session.url,
    sessionId: session.id
  };
}

/**
 * Get checkout session details
 */
async function getCheckoutSession(sessionId) {
  return stripe.checkout.sessions.retrieve(sessionId);
}

module.exports = {
  createCheckoutSession,
  getCheckoutSession,
  TIER_LIMITS
};
