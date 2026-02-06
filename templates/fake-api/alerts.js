/**
 * Honeyclaw Real-Time Alert Module (Node.js)
 * 
 * Sends alerts to webhooks (Slack, Discord, PagerDuty, generic).
 * 
 * Environment variables:
 *   ALERT_WEBHOOK_URL        - Primary webhook URL
 *   ALERT_SEVERITY_THRESHOLD - Minimum severity (DEBUG/INFO/LOW/MEDIUM/HIGH/CRITICAL)
 *   HONEYPOT_ID              - Honeypot identifier
 *   PAGERDUTY_ROUTING_KEY    - PagerDuty routing key (optional)
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');
const crypto = require('crypto');

// Severity levels
const Severity = {
    DEBUG: 0,
    INFO: 1,
    LOW: 2,
    MEDIUM: 3,
    HIGH: 4,
    CRITICAL: 5
};

// Webhook type detection
function detectWebhookType(url) {
    const urlLower = url.toLowerCase();
    if (urlLower.includes('hooks.slack.com')) return 'slack';
    if (urlLower.includes('discord.com/api/webhooks') || urlLower.includes('discordapp.com/api/webhooks')) return 'discord';
    if (urlLower.includes('events.pagerduty.com')) return 'pagerduty';
    return 'generic';
}

// Built-in alert rules
const BUILTIN_RULES = [
    {
        name: 'successful_auth',
        description: 'Successful authentication detected in honeypot',
        severity: Severity.CRITICAL,
        eventTypes: ['auth_success', 'login_success', 'session_established'],
        tags: ['auth', 'critical', 'immediate'],
        dedupWindowSec: 60
    },
    {
        name: 'rate_limit_bypass',
        description: 'Potential rate limit bypass detected',
        severity: Severity.HIGH,
        eventTypes: ['rate_limit_*'],
        conditions: { count: (c) => c && parseInt(c) > 50 },
        tags: ['evasion', 'rate_limit'],
        dedupWindowSec: 600
    },
    {
        name: 'exfil_attempt',
        description: 'Potential data exfiltration attempt',
        severity: Severity.HIGH,
        eventTypes: ['api_request'],
        conditions: { 'request.path': /\/(download|export|backup|dump)/i },
        tags: ['exfiltration', 'data_theft']
    },
    {
        name: 'admin_endpoint_access',
        description: 'Admin endpoint access attempt',
        severity: Severity.MEDIUM,
        eventTypes: ['api_request'],
        conditions: { 'request.path': /\/(admin|internal|management|debug)/i },
        tags: ['recon', 'admin']
    },
    {
        name: 'sqli_attempt',
        description: 'SQL injection attempt detected',
        severity: Severity.MEDIUM,
        eventTypes: ['api_request'],
        conditions: { 'request.path': /(%27|'|--|;|\/\*|\*\/|union.*select|select.*from)/i },
        tags: ['injection', 'sqli']
    },
    {
        name: 'path_traversal',
        description: 'Path traversal attempt detected',
        severity: Severity.MEDIUM,
        eventTypes: ['api_request'],
        conditions: { 'request.path': /(\.\.\/|\.\.\\|%2e%2e%2f)/i },
        tags: ['traversal', 'lfi']
    },
    {
        name: 'api_enumeration',
        description: 'API enumeration activity detected',
        severity: Severity.LOW,
        eventTypes: ['api_request'],
        conditions: { 'response.status': (s) => s === 404 },
        tags: ['recon', 'enumeration'],
        dedupWindowSec: 300
    }
];

// Deduplication cache
const dedupCache = new Map();

// Format for Slack
function formatSlack(alert, honeypotId) {
    const colors = {
        CRITICAL: '#FF0000',
        HIGH: '#FF6600',
        MEDIUM: '#FFCC00',
        LOW: '#00CC00',
        INFO: '#0066FF',
        DEBUG: '#999999'
    };
    const emojis = {
        CRITICAL: '🚨',
        HIGH: '⚠️',
        MEDIUM: '⚡',
        LOW: '📋',
        INFO: 'ℹ️',
        DEBUG: '🔍'
    };
    
    const severity = Object.keys(Severity).find(k => Severity[k] === alert.severity) || 'UNKNOWN';
    const fields = [
        { title: 'Honeypot', value: honeypotId, short: true },
        { title: 'Severity', value: `${emojis[severity] || '📢'} ${severity}`, short: true }
    ];
    
    if (alert.event?.source?.ip) {
        fields.push({ title: 'Source IP', value: `\`${alert.event.source.ip}\``, short: true });
    }
    if (alert.event?.request?.path) {
        fields.push({ title: 'Path', value: `\`${alert.event.request.path}\``, short: true });
    }
    if (alert.tags?.length) {
        fields.push({ title: 'Tags', value: alert.tags.map(t => `\`${t}\``).join(', '), short: true });
    }
    
    return {
        attachments: [{
            color: colors[severity] || '#999999',
            title: `${emojis[severity] || '📢'} ${alert.description}`,
            text: `Rule: \`${alert.rule}\``,
            fields,
            footer: `Honeyclaw Alert | ${new Date().toISOString()}`,
            ts: Math.floor(Date.now() / 1000)
        }]
    };
}

// Format for Discord
function formatDiscord(alert, honeypotId) {
    const colors = {
        CRITICAL: 16711680,
        HIGH: 16744448,
        MEDIUM: 16763904,
        LOW: 52224,
        INFO: 26367,
        DEBUG: 10066329
    };
    const emojis = {
        CRITICAL: '🚨',
        HIGH: '⚠️',
        MEDIUM: '⚡',
        LOW: '📋',
        INFO: 'ℹ️',
        DEBUG: '🔍'
    };
    
    const severity = Object.keys(Severity).find(k => Severity[k] === alert.severity) || 'UNKNOWN';
    const fields = [
        { name: 'Honeypot', value: honeypotId, inline: true },
        { name: 'Severity', value: `${emojis[severity] || '📢'} ${severity}`, inline: true },
        { name: 'Rule', value: `\`${alert.rule}\``, inline: true }
    ];
    
    if (alert.event?.source?.ip) {
        fields.push({ name: 'Source IP', value: `\`${alert.event.source.ip}\``, inline: true });
    }
    if (alert.event?.request?.path) {
        fields.push({ name: 'Path', value: `\`${alert.event.request.path}\``, inline: true });
    }
    
    return {
        embeds: [{
            title: `${emojis[severity] || '📢'} ${alert.description}`,
            color: colors[severity] || 10066329,
            fields,
            footer: { text: 'Honeyclaw Alert' },
            timestamp: new Date().toISOString()
        }]
    };
}

// Format for PagerDuty
function formatPagerDuty(alert, honeypotId, routingKey) {
    const severityMap = {
        CRITICAL: 'critical',
        HIGH: 'error',
        MEDIUM: 'warning',
        LOW: 'info',
        INFO: 'info',
        DEBUG: 'info'
    };
    const severity = Object.keys(Severity).find(k => Severity[k] === alert.severity) || 'INFO';
    
    const dedupKey = crypto.createHash('sha256')
        .update(`${honeypotId}:${alert.rule}:${alert.event?.source?.ip || 'unknown'}`)
        .digest('hex')
        .substring(0, 32);
    
    return {
        routing_key: routingKey,
        event_action: 'trigger',
        dedup_key: dedupKey,
        payload: {
            summary: `[${honeypotId}] ${alert.description}`,
            source: honeypotId,
            severity: severityMap[severity],
            timestamp: new Date().toISOString(),
            custom_details: {
                rule: alert.rule,
                tags: alert.tags,
                event: alert.event
            }
        },
        client: 'Honeyclaw'
    };
}

// Format for generic webhook
function formatGeneric(alert, honeypotId) {
    return {
        honeypot_id: honeypotId,
        alert,
        timestamp: new Date().toISOString()
    };
}

// HTTP POST helper
function httpPost(url, payload) {
    return new Promise((resolve, reject) => {
        const parsedUrl = new URL(url);
        const options = {
            hostname: parsedUrl.hostname,
            port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
            path: parsedUrl.pathname + parsedUrl.search,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'Honeyclaw-Alert/1.0'
            },
            timeout: 10000
        };
        
        const transport = parsedUrl.protocol === 'https:' ? https : http;
        const req = transport.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    resolve(data);
                } else {
                    reject(new Error(`HTTP ${res.statusCode}: ${data.substring(0, 200)}`));
                }
            });
        });
        
        req.on('error', reject);
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });
        
        req.write(JSON.stringify(payload));
        req.end();
    });
}

// Get nested value from object
function getNestedValue(obj, path) {
    return path.split('.').reduce((current, key) => current?.[key], obj);
}

// Match pattern
function matchPattern(value, pattern) {
    if (value === undefined || value === null) return pattern === null;
    if (pattern instanceof RegExp) return pattern.test(String(value));
    if (typeof pattern === 'function') return pattern(value);
    if (Array.isArray(pattern)) return pattern.includes(value);
    return value === pattern;
}

// Check if event matches rule
function matchesRule(event, eventType, rule) {
    // Check event type
    if (rule.eventTypes && rule.eventTypes.length > 0) {
        const matches = rule.eventTypes.some(pattern => {
            if (pattern.includes('*')) {
                const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
                return regex.test(eventType);
            }
            return pattern === eventType;
        });
        if (!matches) return false;
    }
    
    // Check conditions
    if (rule.conditions) {
        for (const [path, pattern] of Object.entries(rule.conditions)) {
            const value = getNestedValue(event, path);
            if (!matchPattern(value, pattern)) return false;
        }
    }
    
    return true;
}

// Generate dedup hash
function getDedupHash(rule, event) {
    const ip = event?.source?.ip || event?.ip || 'unknown';
    return `${rule.name}:${ip}`;
}

// Clean old dedup entries
function cleanDedupCache() {
    const now = Date.now();
    for (const [hash, entry] of dedupCache.entries()) {
        if (now - entry.time > 86400000) { // 24 hours max
            dedupCache.delete(hash);
        }
    }
}

// Alert dispatcher class
class AlertDispatcher {
    constructor(options = {}) {
        this.webhookUrl = options.webhookUrl || process.env.ALERT_WEBHOOK_URL;
        this.honeypotId = options.honeypotId || process.env.HONEYPOT_ID || 'honeyclaw-api';
        this.pagerdutyKey = options.pagerdutyKey || process.env.PAGERDUTY_ROUTING_KEY;
        
        const threshold = (options.minSeverity || process.env.ALERT_SEVERITY_THRESHOLD || 'LOW').toUpperCase();
        this.minSeverity = Severity[threshold] ?? Severity.LOW;
        
        this.enabled = !!this.webhookUrl;
        this.webhookType = this.webhookUrl ? detectWebhookType(this.webhookUrl) : null;
        
        this.rules = [...BUILTIN_RULES];
        this.stats = { sent: 0, failed: 0, processed: 0 };
        
        // Periodic cleanup
        setInterval(() => cleanDedupCache(), 60000);
        
        if (this.enabled) {
            console.log(`[INFO] Alerting enabled: ${this.webhookType} webhook`);
        }
    }
    
    processEvent(event, eventType) {
        if (!this.enabled) return;
        this.stats.processed++;
        
        const now = Date.now();
        
        for (const rule of this.rules) {
            if (rule.severity < this.minSeverity) continue;
            if (!matchesRule(event, eventType, rule)) continue;
            
            // Deduplication
            const dedupHash = getDedupHash(rule, event);
            const dedupWindow = (rule.dedupWindowSec || 300) * 1000;
            const cached = dedupCache.get(dedupHash);
            
            if (cached && now - cached.time < dedupWindow) {
                cached.count++;
                continue;
            }
            
            dedupCache.set(dedupHash, { time: now, count: 1 });
            
            // Create alert
            const severity = Object.keys(Severity).find(k => Severity[k] === rule.severity);
            const alert = {
                rule: rule.name,
                description: rule.description,
                severity: rule.severity,
                severityName: severity,
                tags: rule.tags || [],
                eventType,
                event
            };
            
            this.dispatch(alert);
        }
    }
    
    dispatch(alert) {
        let payload;
        
        switch (this.webhookType) {
            case 'slack':
                payload = formatSlack(alert, this.honeypotId);
                break;
            case 'discord':
                payload = formatDiscord(alert, this.honeypotId);
                break;
            case 'pagerduty':
                payload = formatPagerDuty(alert, this.honeypotId, this.pagerdutyKey);
                break;
            default:
                payload = formatGeneric(alert, this.honeypotId);
        }
        
        // Send asynchronously
        httpPost(this.webhookUrl, payload)
            .then(() => { this.stats.sent++; })
            .catch(err => {
                this.stats.failed++;
                console.error(`[ALERT] Failed: ${err.message}`);
            });
    }
    
    sendTestAlert() {
        const alert = {
            rule: 'test_alert',
            description: 'Test Alert - Honeyclaw Alert Pipeline',
            severity: Severity.INFO,
            severityName: 'INFO',
            tags: ['test'],
            eventType: 'test',
            event: {
                message: 'This is a test alert from Honeyclaw',
                source: { ip: '127.0.0.1' },
                timestamp: new Date().toISOString()
            }
        };
        
        this.dispatch(alert);
        console.log('[TEST] Alert dispatched');
    }
}

// Singleton instance
let _dispatcher = null;

function getDispatcher() {
    if (!_dispatcher) {
        _dispatcher = new AlertDispatcher();
    }
    return _dispatcher;
}

function alert(event, eventType) {
    getDispatcher().processEvent(event, eventType);
}

module.exports = {
    AlertDispatcher,
    getDispatcher,
    alert,
    Severity,
    BUILTIN_RULES
};
