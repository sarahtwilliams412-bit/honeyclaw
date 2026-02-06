/**
 * Honey Claw Telegram Bot
 * 
 * MVP implementation - responds to commands, queues deployments
 * Full automation comes in v2
 */

const { Bot, session } = require('grammy');
const { sanitizeUserMessage, sanitizeError } = require('../src/utils/log-sanitizer');

// ============================================================
// Configuration
// ============================================================

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const ADMIN_IDS = (process.env.ADMIN_USER_IDS || '').split(',').map(Number).filter(Boolean);

if (!BOT_TOKEN) {
  console.error('❌ TELEGRAM_BOT_TOKEN not set');
  console.error('Get one from @BotFather on Telegram');
  process.exit(1);
}

// ============================================================
// In-Memory State (MVP - replace with DB in production)
// ============================================================

const deployments = new Map();  // userId -> [{id, template, status, createdAt}]
const deployQueue = [];         // Pending deployments

const TEMPLATES = {
  ssh: { name: 'SSH (Cowrie)', port: 22, description: 'Catch brute force attacks' },
  web: { name: 'Web Application', port: 80, description: 'Trap scanners and bots' },
  mysql: { name: 'MySQL Database', port: 3306, description: 'Lure database attackers' },
};

const FREE_LIMIT = 1;

// ============================================================
// Bot Setup
// ============================================================

const bot = new Bot(BOT_TOKEN);

// Session middleware for per-user state
bot.use(session({
  initial: () => ({
    lastCommand: null,
    commandCount: 0,
  }),
}));

// Logging middleware (sanitized - no sensitive data in logs)
bot.use(async (ctx, next) => {
  const start = Date.now();
  const user = ctx.from?.username || ctx.from?.id || 'unknown';
  // Sanitize message content to prevent password/token leaks
  const safeMessage = sanitizeUserMessage(ctx.message?.text);
  console.log(`[${new Date().toISOString()}] ${user}: ${safeMessage}`);
  await next();
  console.log(`[${new Date().toISOString()}] Response time: ${Date.now() - start}ms`);
});

// ============================================================
// Commands
// ============================================================

bot.command('start', async (ctx) => {
  const welcome = `🍯 *Welcome to Honey Claw!*

Deploy cloud honeypots in seconds. Catch attackers, collect intel.

*What we offer:*
• SSH honeypots - Catch brute force attacks
• Web honeypots - Trap scanners and bots  
• MySQL honeypots - Lure database attackers

*Commands:*
/deploy <template> - Launch a honeypot
/status - Check your deployments
/logs - View recent attacks
/pricing - See plans & payment

Ready to set a trap? Try: \`/deploy ssh\``;

  await ctx.reply(welcome, { parse_mode: 'Markdown' });
});

bot.command('help', async (ctx) => {
  const help = `🍯 *Honey Claw Commands*

/start - Welcome & intro
/deploy <template> - Deploy honeypot
/status - Check your honeypots
/logs - View attack logs
/pricing - Plans & payment
/help - This message

*Templates:* ssh, web, mysql

Need help? @honeyclaw\\_support`;

  await ctx.reply(help, { parse_mode: 'Markdown' });
});

bot.command('deploy', async (ctx) => {
  const userId = ctx.from.id;
  const args = ctx.message.text.split(' ').slice(1);
  const template = args[0]?.toLowerCase();

  // Validate template
  if (!template) {
    return ctx.reply(`❌ Please specify a template

Usage: \`/deploy <template>\`

Available templates:
• ssh - SSH honeypot (port 22)
• web - Web honeypot (port 80/443)
• mysql - MySQL honeypot (port 3306)

Example: \`/deploy ssh\``, { parse_mode: 'Markdown' });
  }

  if (!TEMPLATES[template]) {
    return ctx.reply(`❌ Unknown template: "${template}"

Available templates:
• ssh - SSH honeypot (port 22)
• web - Web honeypot (port 80/443)
• mysql - MySQL honeypot (port 3306)

Try: \`/deploy ssh\``, { parse_mode: 'Markdown' });
  }

  // Check limit
  const userDeploys = deployments.get(userId) || [];
  const activeCount = userDeploys.filter(d => d.status === 'active').length;
  
  if (activeCount >= FREE_LIMIT) {
    return ctx.reply(`⚠️ You've reached your honeypot limit.

Current plan: Free (${FREE_LIMIT} honeypot)
Active: ${activeCount}/${FREE_LIMIT}

Upgrade for more: /pricing`);
  }

  // Create deployment
  const deployId = `${template}-${Math.random().toString(36).substr(2, 4)}`;
  const deployment = {
    id: deployId,
    template,
    status: 'queued',
    createdAt: new Date(),
    userId,
  };

  // Store deployment
  if (!deployments.has(userId)) {
    deployments.set(userId, []);
  }
  deployments.get(userId).push(deployment);
  deployQueue.push(deployment);

  const tmpl = TEMPLATES[template];
  await ctx.reply(`🚀 *Deploying ${tmpl.name} honeypot...*

Template: ${template} (${tmpl.description})
Region: auto (nearest)
Status: ⏳ Queued

You'll receive a notification when ready (~2 min).

Track progress: /status`, { parse_mode: 'Markdown' });

  // Simulate deployment completion (MVP only)
  setTimeout(async () => {
    deployment.status = 'active';
    deployment.ip = `142.93.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    try {
      await ctx.reply(`✅ *Honeypot Ready!*

ID: ${deployId}
IP: ${deployment.ip}
Port: ${tmpl.port}
Status: 🟢 Active

Your honeypot is now live and collecting data.
Check activity: /logs`, { parse_mode: 'Markdown' });
    } catch (e) {
      console.error('Failed to send completion notification:', e.message);
    }
  }, 5000); // 5 seconds for demo
});

bot.command('status', async (ctx) => {
  const userId = ctx.from.id;
  const userDeploys = deployments.get(userId) || [];
  const active = userDeploys.filter(d => d.status === 'active');

  if (active.length === 0) {
    return ctx.reply(`📊 *No Active Honeypots*

You haven't deployed any honeypots yet.

Get started: \`/deploy ssh\``, { parse_mode: 'Markdown' });
  }

  let response = '📊 *Your Honeypots*\n\n';
  
  for (const d of active) {
    const tmpl = TEMPLATES[d.template];
    const uptime = formatUptime(Date.now() - d.createdAt.getTime());
    const attacks = Math.floor(Math.random() * 100) + 10; // Mock data
    
    response += `┌─ ${d.id} ─────────────────┐
│ Type: ${tmpl.name}
│ IP: ${d.ip || 'Provisioning...'}
│ Status: 🟢 Active
│ Uptime: ${uptime}
│ Attacks: ${attacks} today
└────────────────────────────┘\n\n`;
  }

  response += `/logs - View recent activity`;

  await ctx.reply(response, { parse_mode: 'Markdown' });
});

bot.command('logs', async (ctx) => {
  const userId = ctx.from.id;
  const userDeploys = deployments.get(userId) || [];
  const active = userDeploys.filter(d => d.status === 'active');

  if (active.length === 0) {
    return ctx.reply(`📜 *No Honeypots Active*

Deploy a honeypot first to see attack logs.

Try: \`/deploy ssh\``, { parse_mode: 'Markdown' });
  }

  // Generate mock attack logs
  const mockLogs = generateMockLogs();
  const honeypot = active[0];

  await ctx.reply(`📜 *Recent Attacks* (${honeypot.id})

${mockLogs}

Showing 3 of ${Math.floor(Math.random() * 50) + 20} today
Full export coming in v2`, { parse_mode: 'Markdown' });
});

bot.command('pricing', async (ctx) => {
  const userId = ctx.from.id;
  
  const pricing = `💰 *Honey Claw Pricing*

*FREE TIER*
• 1 honeypot
• 24h log retention
• Basic templates
• $0/month

*HUNTER*
• 5 honeypots
• 30-day retention
• All templates
• API access
• $29/month

*ENTERPRISE*
• Unlimited honeypots
• 1-year retention
• Custom templates
• Priority support
• Contact us

─────────────────────────

Payment: BTC, ETH, USDC accepted

To upgrade, send payment to:
\`BTC: bc1q...honeyclaw\`
\`ETH: 0x...honeyclaw\`

Include your Telegram ID in memo:
Your ID: \`${userId}\`

Questions? @honeyclaw\\_support`;

  await ctx.reply(pricing, { parse_mode: 'Markdown' });
});

// ============================================================
// Admin Commands
// ============================================================

bot.command('admin', async (ctx) => {
  const userId = ctx.from.id;
  
  if (!ADMIN_IDS.includes(userId)) {
    return; // Silently ignore non-admins
  }

  const args = ctx.message.text.split(' ').slice(1);
  const subcommand = args[0];

  if (subcommand === 'stats') {
    const totalUsers = deployments.size;
    const totalDeploys = Array.from(deployments.values()).flat().length;
    const activeDeploys = Array.from(deployments.values()).flat().filter(d => d.status === 'active').length;
    const queueSize = deployQueue.length;

    return ctx.reply(`📈 *Admin Stats*

Users: ${totalUsers}
Total deployments: ${totalDeploys}
Active honeypots: ${activeDeploys}
Queue size: ${queueSize}`, { parse_mode: 'Markdown' });
  }

  await ctx.reply(`*Admin Commands*

/admin stats - Global statistics
/admin user <id> - User lookup (coming soon)
/admin broadcast <msg> - Broadcast (coming soon)`, { parse_mode: 'Markdown' });
});

// ============================================================
// Helpers
// ============================================================

function formatUptime(ms) {
  const hours = Math.floor(ms / 3600000);
  const minutes = Math.floor((ms % 3600000) / 60000);
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function generateMockLogs() {
  const now = new Date();
  const countries = ['CN', 'RU', 'DE', 'NL', 'US', 'BR', 'KR'];
  const users = ['root', 'admin', 'ubuntu', 'postgres', 'test', 'user', 'oracle'];
  
  const logs = [];
  for (let i = 0; i < 3; i++) {
    const time = new Date(now - i * 5 * 60000);
    const timeStr = time.toTimeString().slice(0, 5);
    const ip = `${Math.floor(Math.random() * 200) + 20}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    const country = countries[Math.floor(Math.random() * countries.length)];
    const attempts = Math.floor(Math.random() * 150) + 5;
    const user = users[Math.floor(Math.random() * users.length)];

    if (attempts > 20) {
      logs.push(`[${timeStr}] 🔴 SSH brute force
        IP: ${ip} (${country})
        Attempts: ${attempts}
        Users tried: ${users.slice(0, 3).join(', ')}`);
    } else {
      logs.push(`[${timeStr}] 🟡 SSH login attempt
        IP: ${ip} (${country})
        User: ${user}
        Pass: ******* (${Math.floor(Math.random() * 8) + 4} chars)`);
    }
  }
  
  return logs.join('\n\n');
}

// ============================================================
// Error Handling
// ============================================================

bot.catch((err) => {
  // Sanitize error to prevent sensitive data in logs (e.g., tokens in stack traces)
  console.error('Bot error:', sanitizeError(err));
});

// ============================================================
// Start Bot
// ============================================================

console.log('🍯 Honey Claw Bot starting...');
bot.start({
  onStart: (botInfo) => {
    console.log(`✅ Bot running as @${botInfo.username}`);
    // Note: Admin IDs intentionally not logged to prevent enumeration
    console.log(`Admins configured: ${ADMIN_IDS.length > 0 ? ADMIN_IDS.length : 0}`);
  },
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('Shutting down...');
  bot.stop();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('Shutting down...');
  bot.stop();
  process.exit(0);
});
