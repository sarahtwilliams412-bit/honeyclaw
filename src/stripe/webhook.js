const Stripe = require('stripe');
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

/**
 * Verify and parse Stripe webhook
 * @param {Buffer} payload - Raw request body
 * @param {string} signature - Stripe-Signature header
 * @returns {Stripe.Event}
 */
function constructEvent(payload, signature) {
  return stripe.webhooks.constructEvent(
    payload,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET
  );
}

/**
 * Handle Stripe webhook events
 * @param {Stripe.Event} event
 * @param {object} handlers - Event handlers {onSubscribed, onRenewed, onFailed, onCancelled}
 */
async function handleWebhookEvent(event, handlers) {
  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      if (session.mode === 'subscription') {
        const telegramUserId = session.metadata?.telegram_user_id;
        const tier = session.metadata?.tier;
        const customerId = session.customer;
        const subscriptionId = session.subscription;
        
        if (handlers.onSubscribed) {
          await handlers.onSubscribed({
            telegramUserId,
            tier,
            customerId,
            subscriptionId
          });
        }
      }
      break;
    }

    case 'invoice.paid': {
      const invoice = event.data.object;
      const subscriptionId = invoice.subscription;
      const customerId = invoice.customer;
      
      if (handlers.onRenewed) {
        await handlers.onRenewed({
          customerId,
          subscriptionId,
          amountPaid: invoice.amount_paid
        });
      }
      break;
    }

    case 'invoice.payment_failed': {
      const invoice = event.data.object;
      const customerId = invoice.customer;
      
      if (handlers.onFailed) {
        await handlers.onFailed({
          customerId,
          subscriptionId: invoice.subscription,
          attemptCount: invoice.attempt_count
        });
      }
      break;
    }

    case 'customer.subscription.deleted': {
      const subscription = event.data.object;
      
      if (handlers.onCancelled) {
        await handlers.onCancelled({
          customerId: subscription.customer,
          subscriptionId: subscription.id
        });
      }
      break;
    }

    default:
      console.log(`Unhandled event type: ${event.type}`);
  }
}

/**
 * Express middleware for Stripe webhooks
 */
function webhookMiddleware(handlers) {
  return async (req, res) => {
    const signature = req.headers['stripe-signature'];
    
    try {
      const event = constructEvent(req.body, signature);
      await handleWebhookEvent(event, handlers);
      res.json({ received: true });
    } catch (err) {
      console.error('Webhook error:', err.message);
      res.status(400).send(`Webhook Error: ${err.message}`);
    }
  };
}

module.exports = {
  constructEvent,
  handleWebhookEvent,
  webhookMiddleware
};
