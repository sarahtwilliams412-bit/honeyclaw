# Honey Claw Telegram Bot

Telegram interface for deploying and managing cloud honeypots.

## Overview

This bot allows users to:
- Deploy honeypot instances with one command
- Monitor active honeypots
- View attack logs in real-time
- Manage billing via crypto payments

## Setup

### 1. Create Bot via BotFather

1. Open Telegram and search for `@BotFather`
2. Send `/newbot`
3. Choose a name: `Honey Claw` (display name)
4. Choose a username: `honeyclaw_bot` (must end in `bot`)
5. Copy the API token (looks like: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)

### 2. Environment Setup

```bash
# Install dependencies
npm install

# Set environment variables
export TELEGRAM_BOT_TOKEN="your-token-here"
export HONEYCLAW_API_URL="http://localhost:3000"  # Internal API

# Run the bot
npm start
```

### 3. Development

```bash
# Run with auto-reload
npm run dev
```

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Telegram   │────▶│  Bot Handler │────▶│ Honeyclaw   │
│   Users     │◀────│  (this)      │◀────│ Backend API │
└─────────────┘     └──────────────┘     └─────────────┘
```

## Commands

| Command | Description |
|---------|-------------|
| `/start` | Welcome message, explain service |
| `/deploy <template>` | Deploy a new honeypot |
| `/status` | Check your honeypot status |
| `/logs` | Get recent attack logs |
| `/pricing` | Show pricing and payment wallet |
| `/help` | List all commands |

## Templates

MVP templates:
- `ssh` - SSH honeypot (Cowrie-based)
- `web` - Web application honeypot
- `mysql` - MySQL honeypot

## Tech Stack

- **Runtime:** Node.js 20+
- **Framework:** grammy (Telegram Bot framework)
- **Why grammy:** Modern, TypeScript-first, excellent middleware support

## File Structure

```
bot/
├── README.md           # This file
├── commands.md         # Detailed command specifications
├── handler.js          # Main bot code
├── package.json        # Dependencies
└── .env.example        # Environment template
```

## MVP Scope

For MVP, the bot will:
- ✅ Respond to all commands with appropriate messages
- ✅ Queue deployment requests (stored in memory/file)
- ✅ Show mock status and pricing
- ⏳ Full automation (v2) - actual infrastructure deployment

## Security Notes

- Bot token must be kept secret (use env vars, never commit)
- Validate all user input before processing
- Rate limit commands to prevent abuse
- User IDs are used for auth (Telegram provides verified IDs)
