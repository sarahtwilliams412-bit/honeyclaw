const Stripe = require('stripe');
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// In-memory store for MVP - replace with database
const customerStore = new Map();

/**
 * Get or create Stripe customer for Telegram user
 */
async function getOrCreateCustomer(telegramUserId, telegramUsername) {
  // Check local cache first
  if (customerStore.has(telegramUserId)) {
    return customerStore.get(telegramUserId);
  }

  // Search Stripe for existing customer
  const existing = await stripe.customers.search({
    query: `metadata['telegram_user_id']:'${telegramUserId}'`
  });

  if (existing.data.length > 0) {
    const customer = existing.data[0];
    customerStore.set(telegramUserId, customer);
    return customer;
  }

  // Create new customer
  const customer = await stripe.customers.create({
    metadata: {
      telegram_user_id: telegramUserId,
      telegram_username: telegramUsername || ''
    }
  });

  customerStore.set(telegramUserId, customer);
  return customer;
}

/**
 * Get customer's active subscription
 */
async function getActiveSubscription(customerId) {
  const subscriptions = await stripe.subscriptions.list({
    customer: customerId,
    status: 'active',
    limit: 1
  });

  return subscriptions.data[0] || null;
}

/**
 * Check if user has active subscription
 */
async function hasActiveSubscription(telegramUserId) {
  const cached = customerStore.get(telegramUserId);
  if (!cached) return false;

  const subscription = await getActiveSubscription(cached.id);
  return subscription !== null;
}

/**
 * Get subscription tier for user
 */
async function getUserTier(telegramUserId) {
  const cached = customerStore.get(telegramUserId);
  if (!cached) return null;

  const subscription = await getActiveSubscription(cached.id);
  if (!subscription) return null;

  return subscription.metadata?.tier || 'starter';
}

/**
 * Cancel subscription
 */
async function cancelSubscription(telegramUserId) {
  const cached = customerStore.get(telegramUserId);
  if (!cached) return false;

  const subscription = await getActiveSubscription(cached.id);
  if (!subscription) return false;

  await stripe.subscriptions.cancel(subscription.id);
  return true;
}

/**
 * Link Telegram user to Stripe customer (after checkout)
 */
function linkCustomer(telegramUserId, stripeCustomer) {
  customerStore.set(telegramUserId, stripeCustomer);
}

module.exports = {
  getOrCreateCustomer,
  getActiveSubscription,
  hasActiveSubscription,
  getUserTier,
  cancelSubscription,
  linkCustomer
};
