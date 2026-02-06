/**
 * Honey Claw - Fake API Honeypot Server
 * Version: 1.2.0 (real-time alerting)
 * 
 * Medium-interaction API honeypot that simulates a REST API
 * and logs all interactions for threat detection.
 * 
 * Rate limit configuration via environment variables:
 *   RATELIMIT_ENABLED          - Enable rate limiting (default: true)
 *   RATELIMIT_CONN_PER_MIN     - Max requests per IP per minute (default: 10)
 *   RATELIMIT_AUTH_PER_HOUR    - Max auth attempts per IP per hour (default: 100)
 *   RATELIMIT_CLEANUP_INTERVAL - Cleanup interval in seconds (default: 60)
 * 
 * Alert configuration via environment variables:
 *   ALERT_WEBHOOK_URL          - Webhook URL for alerts (Slack/Discord/PagerDuty)
 *   ALERT_SEVERITY_THRESHOLD   - Minimum severity (DEBUG/INFO/LOW/MEDIUM/HIGH/CRITICAL)
 *   HONEYPOT_ID                - Honeypot identifier for alerts
 */

const express = require('express');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

// Real-time alerting (optional)
let alertDispatcher = null;
try {
    const { getDispatcher } = require('./alerts');
    alertDispatcher = getDispatcher();
} catch (e) {
    console.log('[INFO] Alerting module not available');
}

// =============================================================================
// Rate Limiting (inline to avoid module resolution issues in container)
// =============================================================================
class RateLimiter {
    constructor() {
        this.enabled = (process.env.RATELIMIT_ENABLED || 'true').toLowerCase() === 'true';
        this.connPerMin = parseInt(process.env.RATELIMIT_CONN_PER_MIN || '10', 10);
        this.authPerHour = parseInt(process.env.RATELIMIT_AUTH_PER_HOUR || '100', 10);
        this.cleanupInterval = parseInt(process.env.RATELIMIT_CLEANUP_INTERVAL || '60', 10);
        
        this._connCounts = new Map();
        this._authCounts = new Map();
        this._blockedConns = 0;
        this._blockedAuths = 0;
        
        this._cleanupTimer = setInterval(() => this._cleanup(), this.cleanupInterval * 1000);
        
        if (this.enabled) {
            console.log(`[INFO] Rate limiting enabled: ${this.connPerMin}/min connections, ${this.authPerHour}/hr auth`);
        }
    }
    
    checkConnection(ip) {
        if (!this.enabled) return { allowed: true };
        
        const now = Date.now();
        const minuteAgo = now - 60000;
        
        let timestamps = this._connCounts.get(ip) || [];
        timestamps = timestamps.filter(t => t > minuteAgo);
        
        if (timestamps.length >= this.connPerMin) {
            this._blockedConns++;
            this._logRateLimit('connection', ip, timestamps.length, this.connPerMin, '1m');
            this._connCounts.set(ip, timestamps);
            return { allowed: false, reason: `Connection rate limit exceeded (${this.connPerMin}/min)` };
        }
        
        timestamps.push(now);
        this._connCounts.set(ip, timestamps);
        return { allowed: true };
    }
    
    checkAuth(ip) {
        if (!this.enabled) return { allowed: true };
        
        const now = Date.now();
        const hourAgo = now - 3600000;
        
        let timestamps = this._authCounts.get(ip) || [];
        timestamps = timestamps.filter(t => t > hourAgo);
        
        if (timestamps.length >= this.authPerHour) {
            this._blockedAuths++;
            this._logRateLimit('auth', ip, timestamps.length, this.authPerHour, '1h');
            this._authCounts.set(ip, timestamps);
            return { allowed: false, reason: `Auth rate limit exceeded (${this.authPerHour}/hour)` };
        }
        
        timestamps.push(now);
        this._authCounts.set(ip, timestamps);
        return { allowed: true };
    }
    
    _logRateLimit(type, ip, count, limit, window) {
        const event = {
            timestamp: new Date().toISOString(),
            event: `rate_limit_${type}`,
            ip,
            count,
            limit,
            window,
            total_blocked: type === 'connection' ? this._blockedConns : this._blockedAuths
        };
        console.log(JSON.stringify(event));
        appendLog(event);
    }
    
    _cleanup() {
        const now = Date.now();
        const minuteAgo = now - 60000;
        const hourAgo = now - 3600000;
        
        for (const [ip, timestamps] of this._connCounts.entries()) {
            const valid = timestamps.filter(t => t > minuteAgo);
            if (valid.length === 0) this._connCounts.delete(ip);
            else this._connCounts.set(ip, valid);
        }
        
        for (const [ip, timestamps] of this._authCounts.entries()) {
            const valid = timestamps.filter(t => t > hourAgo);
            if (valid.length === 0) this._authCounts.delete(ip);
            else this._authCounts.set(ip, valid);
        }
    }
    
    getStats() {
        return {
            enabled: this.enabled,
            config: { connPerMin: this.connPerMin, authPerHour: this.authPerHour },
            blocked: { connections: this._blockedConns, auths: this._blockedAuths }
        };
    }
}

const rateLimiter = new RateLimiter();

// =============================================================================
// Input Validation Utilities
// =============================================================================
const VALIDATION_LIMITS = {
    MAX_USERNAME_LENGTH: 256,
    MAX_PASSWORD_LENGTH: 1024,
    MAX_PATH_LENGTH: 4096,
    MAX_HEADER_LENGTH: 8192,
    MAX_BODY_LENGTH: 65536,  // 64KB
    MAX_LOG_LINE_LENGTH: 16384,  // 16KB
    MAX_QUERY_PARAM_LENGTH: 1024
};

function sanitizeForLog(text, maxLength = 1024) {
    if (text === null || text === undefined) return '<null>';
    if (typeof text !== 'string') {
        try {
            text = String(text);
        } catch {
            return '<unconvertible>';
        }
    }
    
    // Truncate first
    text = text.slice(0, maxLength);
    
    // Replace control characters
    return text.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, char => 
        `\\x${char.charCodeAt(0).toString(16).padStart(2, '0')}`
    );
}

function validateIp(ip) {
    if (!ip || typeof ip !== 'string') return { ip: 'unknown', valid: false };
    
    ip = ip.slice(0, 64);  // Max reasonable length
    
    // IPv4 pattern
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    // IPv6 pattern (simplified)
    const ipv6Pattern = /^[0-9a-fA-F:]+$/;
    
    if (ipv4Pattern.test(ip)) {
        const octets = ip.split('.').map(Number);
        const valid = octets.every(o => o >= 0 && o <= 255);
        return { ip, valid };
    }
    if (ipv6Pattern.test(ip)) {
        return { ip, valid: true };
    }
    
    return { ip: sanitizeForLog(ip, 64), valid: false };
}

function validateUsername(username) {
    if (username === null || username === undefined) return { value: '<null>', valid: false };
    if (typeof username !== 'string') return { value: '<invalid-type>', valid: false };
    
    const valid = username.length <= VALIDATION_LIMITS.MAX_USERNAME_LENGTH;
    const sanitized = username.slice(0, VALIDATION_LIMITS.MAX_USERNAME_LENGTH)
        .replace(/[^a-zA-Z0-9._@+\-]/g, '_');
    
    return { value: sanitized || '<empty>', valid };
}

function validatePassword(password) {
    if (password === null || password === undefined) return { length: 0, valid: true };
    if (typeof password !== 'string') return { length: -1, valid: false };
    
    const valid = password.length <= VALIDATION_LIMITS.MAX_PASSWORD_LENGTH;
    return { length: Math.min(password.length, VALIDATION_LIMITS.MAX_PASSWORD_LENGTH), valid };
}

function sanitizePath(path) {
    if (!path || typeof path !== 'string') return { value: '/', valid: true };
    
    const valid = path.length <= VALIDATION_LIMITS.MAX_PATH_LENGTH;
    let sanitized = path.slice(0, VALIDATION_LIMITS.MAX_PATH_LENGTH);
    
    // Remove path traversal for logging
    sanitized = sanitized.replace(/\.\.\//g, '_parent_/');
    sanitized = sanitized.replace(/\.\.\\/g, '_parent_\\');
    sanitized = sanitized.replace(/\x00/g, '');
    
    return { value: sanitized, valid };
}

function sanitizeQueryParams(query) {
    if (!query || typeof query !== 'object') return {};
    
    const sanitized = {};
    let count = 0;
    
    for (const [key, value] of Object.entries(query)) {
        if (count >= 50) {
            sanitized._truncated = true;
            break;
        }
        
        const safeKey = sanitizeForLog(key, 256);
        let safeValue;
        
        if (typeof value === 'string') {
            safeValue = sanitizeForLog(value, VALIDATION_LIMITS.MAX_QUERY_PARAM_LENGTH);
        } else if (Array.isArray(value)) {
            safeValue = value.slice(0, 10).map(v => 
                sanitizeForLog(String(v), VALIDATION_LIMITS.MAX_QUERY_PARAM_LENGTH)
            );
        } else {
            safeValue = sanitizeForLog(String(value), VALIDATION_LIMITS.MAX_QUERY_PARAM_LENGTH);
        }
        
        sanitized[safeKey] = safeValue;
        count++;
    }
    
    return sanitized;
}

function sanitizeBody(body, maxLength = VALIDATION_LIMITS.MAX_BODY_LENGTH) {
    if (!body) return null;
    
    // For objects, stringify and truncate
    if (typeof body === 'object') {
        try {
            const str = JSON.stringify(body);
            if (str.length > maxLength) {
                return { _truncated: true, _original_length: str.length, preview: str.slice(0, 1024) };
            }
            return body;
        } catch {
            return { _error: 'stringify-failed' };
        }
    }
    
    return sanitizeForLog(String(body), maxLength);
}

const app = express();
const PORT = process.env.PORT || 8080;
const HONEYPOT_ID = process.env.HONEYPOT_ID || 'fake-api-default';
const LOG_FILE = '/var/log/honeypot/api.json';

// Fake data for responses
const fakeUsers = require('./data/users.json');

// Middleware
app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting middleware
app.use((req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const result = rateLimiter.checkConnection(ip);
    
    if (!result.allowed) {
        console.log(`[RATELIMIT] Request blocked from ${ip}: ${result.reason}`);
        return res.status(429).json({
            error: 'Too Many Requests',
            message: result.reason,
            retry_after: 60
        });
    }
    next();
});

// Request logging middleware with input validation
app.use((req, res, next) => {
    // Validate source IP
    const rawIp = req.ip || req.connection.remoteAddress || 'unknown';
    const { ip: safeIp, valid: ipValid } = validateIp(rawIp);
    
    // Validate and sanitize path
    const { value: safePath, valid: pathValid } = sanitizePath(req.path);
    
    // Sanitize query params
    const safeQuery = sanitizeQueryParams(req.query);
    
    // Sanitize body
    const safeBody = sanitizeBody(req.body);
    
    const event = {
        timestamp: new Date().toISOString(),
        honeypot_id: HONEYPOT_ID,
        template: 'fake-api',
        request_id: uuidv4(),
        source: {
            ip: safeIp,
            ip_valid: ipValid,
            port: req.connection.remotePort || 0
        },
        request: {
            method: sanitizeForLog(req.method, 16),
            path: safePath,
            path_valid: pathValid,
            query: safeQuery,
            headers: sanitizeHeaders(req.headers),
            body: safeBody
        },
        auth: extractAuth(req),
        detection: detectThreats(req)
    };
    
    // Ensure log line isn't too large
    let logLine = JSON.stringify(event);
    if (logLine.length > VALIDATION_LIMITS.MAX_LOG_LINE_LENGTH) {
        event._truncated = true;
        event._original_length = logLine.length;
        // Remove body to fit
        event.request.body = { _removed: 'log_too_large' };
        logLine = JSON.stringify(event);
    }
    
    // Log to file
    appendLog(event);
    
    // Attach to request for response logging
    req.honeyclawEvent = event;
    
    next();
});

// Detection functions
function detectThreats(req) {
    const threats = [];
    const payload = JSON.stringify({ ...req.query, ...req.body, path: req.path });
    
    // SQL Injection patterns
    const sqlPatterns = [
        /('|")?(\s)*(or|and)(\s)+('|")?(\d)+('|")?(\s)*=(\s)*('|")?(\d)+/i,
        /union(\s)+select/i,
        /;\s*drop\s+table/i,
        /;\s*delete\s+from/i,
        /'\s*or\s+'1'\s*=\s*'1/i
    ];
    
    for (const pattern of sqlPatterns) {
        if (pattern.test(payload)) {
            threats.push({
                type: 'sql_injection',
                pattern: pattern.toString(),
                mitre: 'T1190'
            });
            break;
        }
    }
    
    // XSS patterns
    const xssPatterns = [
        /<script[^>]*>/i,
        /javascript:/i,
        /on\w+\s*=/i,
        /<img[^>]+onerror/i
    ];
    
    for (const pattern of xssPatterns) {
        if (pattern.test(payload)) {
            threats.push({
                type: 'xss',
                pattern: pattern.toString(),
                mitre: 'T1059.007'
            });
            break;
        }
    }
    
    // Path traversal
    if (/\.\.\/|\.\.\\/.test(payload)) {
        threats.push({
            type: 'path_traversal',
            mitre: 'T1083'
        });
    }
    
    // Command injection
    if (/[;&|`$]/.test(payload) && /\b(cat|ls|wget|curl|bash|sh)\b/.test(payload)) {
        threats.push({
            type: 'command_injection',
            mitre: 'T1059'
        });
    }
    
    return threats.length > 0 ? threats : null;
}

function extractAuth(req) {
    const auth = {};
    
    if (req.headers.authorization) {
        // Sanitize auth header for logging (may contain encoded creds)
        auth.header = sanitizeForLog(req.headers.authorization, 256);
        auth.header_length = req.headers.authorization.length;
        auth.header_truncated = req.headers.authorization.length > 256;
        
        if (req.headers.authorization.startsWith('Bearer ')) {
            auth.type = 'bearer';
            // Don't log full token, just first 32 chars
            const token = req.headers.authorization.slice(7);
            auth.token_preview = sanitizeForLog(token.slice(0, 32), 32);
            auth.token_length = token.length;
        } else if (req.headers.authorization.startsWith('Basic ')) {
            auth.type = 'basic';
            try {
                const encoded = req.headers.authorization.slice(6);
                // Limit encoded portion to prevent DoS
                if (encoded.length > 4096) {
                    auth.decode_error = 'too_large';
                } else {
                    const decoded = Buffer.from(encoded, 'base64').toString();
                    const colonIndex = decoded.indexOf(':');
                    if (colonIndex === -1) {
                        auth.decode_error = 'no_colon';
                    } else {
                        const user = decoded.slice(0, colonIndex);
                        const pass = decoded.slice(colonIndex + 1);
                        
                        // Validate username
                        const { value: safeUser, valid: userValid } = validateUsername(user);
                        auth.username = safeUser;
                        auth.username_valid = userValid;
                        
                        // Validate password (don't log content)
                        const { length: passLen, valid: passValid } = validatePassword(pass);
                        auth.password_length = passLen;
                        auth.password_valid = passValid;
                    }
                }
            } catch (e) {
                auth.decode_error = sanitizeForLog(e.message, 64);
            }
        }
    }
    
    if (req.headers['x-api-key']) {
        // Don't log full API key
        const key = req.headers['x-api-key'];
        auth.api_key_preview = sanitizeForLog(key.slice(0, 16), 16);
        auth.api_key_length = key.length;
    }
    
    return Object.keys(auth).length > 0 ? auth : null;
}

function sanitizeHeaders(headers) {
    // Keep relevant headers for analysis
    const keep = [
        'user-agent', 'accept', 'accept-language', 'accept-encoding',
        'content-type', 'content-length', 'origin', 'referer',
        'x-forwarded-for', 'x-real-ip', 'x-api-key', 'authorization'
    ];
    
    const sanitized = {};
    for (const header of keep) {
        if (headers[header]) {
            // Sanitize header value with length limit
            const value = headers[header];
            const maxLen = header === 'authorization' || header === 'x-api-key' 
                ? 256  // Shorter for sensitive headers
                : VALIDATION_LIMITS.MAX_HEADER_LENGTH;
            
            sanitized[header] = sanitizeForLog(String(value), maxLen);
            
            // Note if truncated
            if (String(value).length > maxLen) {
                sanitized[`${header}_truncated`] = true;
            }
        }
    }
    return sanitized;
}

function appendLog(event, eventType = 'api_request') {
    try {
        let line = JSON.stringify(event);
        
        // Final safety check on log line length
        if (line.length > VALIDATION_LIMITS.MAX_LOG_LINE_LENGTH) {
            const truncatedEvent = {
                timestamp: event.timestamp,
                honeypot_id: event.honeypot_id,
                template: event.template,
                request_id: event.request_id,
                _truncated: true,
                _original_length: line.length,
                source: event.source,
                request: {
                    method: event.request?.method,
                    path: event.request?.path
                }
            };
            line = JSON.stringify(truncatedEvent);
        }
        
        fs.appendFileSync(LOG_FILE, line + '\n');
        
        // Send to real-time alert pipeline
        if (alertDispatcher) {
            try {
                alertDispatcher.processEvent(event, eventType);
            } catch (alertErr) {
                console.error('[ALERT] Error:', alertErr.message);
            }
        }
    } catch (e) {
        console.error('Failed to write log:', sanitizeForLog(e.message, 256));
    }
}

// Simulate response delay
function delay(min = 50, max = 200) {
    const ms = Math.floor(Math.random() * (max - min + 1)) + min;
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Routes

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// OpenAPI spec (helps with enumeration detection)
app.get('/.well-known/openapi.json', async (req, res) => {
    await delay();
    res.json({
        openapi: '3.0.0',
        info: { title: 'Internal API', version: '1.0.0' },
        paths: {
            '/api/v1/users': { get: {}, post: {} },
            '/api/v1/users/{id}': { get: {}, put: {}, delete: {} },
            '/api/v1/auth/login': { post: {} },
            '/api/v1/admin/config': { get: {}, put: {} }
        }
    });
});

// Auth endpoints
app.post('/api/v1/auth/login', async (req, res) => {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const { ip: safeIp, valid: ipValid } = validateIp(ip);
    
    // Check auth rate limit
    const authResult = rateLimiter.checkAuth(safeIp);
    if (!authResult.allowed) {
        console.log(`[RATELIMIT] Auth blocked from ${safeIp}: ${authResult.reason}`);
        return res.status(429).json({
            error: 'Too Many Requests',
            message: authResult.reason,
            retry_after: 3600
        });
    }
    
    await delay();
    const { username, password } = req.body || {};
    
    // Validate and log credentials (for threat intel)
    const { value: safeUser, valid: userValid } = validateUsername(username);
    const { length: passLen, valid: passValid } = validatePassword(password);
    
    // Log the auth attempt with validated data
    appendLog({
        timestamp: new Date().toISOString(),
        honeypot_id: HONEYPOT_ID,
        event: 'auth_attempt',
        source_ip: safeIp,
        source_ip_valid: ipValid,
        username: safeUser,
        username_valid: userValid,
        password_length: passLen,
        password_valid: passValid,
        suspicious: !userValid || !passValid
    });
    
    // Always return a fake token (honeypot behavior)
    res.json({
        access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
        token_type: 'bearer',
        expires_in: 3600
    });
});

// User endpoints
app.get('/api/v1/users', async (req, res) => {
    await delay();
    
    if (!req.headers.authorization) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    res.json({
        data: fakeUsers,
        meta: { total: fakeUsers.length, page: 1, per_page: 20 }
    });
});

app.get('/api/v1/users/:id', async (req, res) => {
    await delay();
    
    if (!req.headers.authorization) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const user = fakeUsers.find(u => u.id === parseInt(req.params.id));
    if (user) {
        res.json({ data: user });
    } else {
        res.status(404).json({ error: 'User not found' });
    }
});

// Admin endpoints (high-value decoys)
app.get('/api/v1/admin/config', async (req, res) => {
    await delay();
    
    // Log this as high-priority - admin access attempt
    console.log(`[ALERT] Admin config access from ${req.ip}`);
    
    res.json({
        database: {
            host: 'db.internal.example.com',
            port: 5432,
            name: 'production'
        },
        redis: {
            host: 'redis.internal.example.com',
            port: 6379
        },
        aws: {
            region: 'us-east-1',
            s3_bucket: 'company-data-prod'
        }
    });
});

app.get('/api/v1/internal/debug', async (req, res) => {
    await delay();
    
    res.json({
        environment: 'production',
        version: '2.4.1',
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        env_vars: {
            NODE_ENV: 'production',
            DB_HOST: 'db.internal.example.com',
            REDIS_URL: 'redis://redis.internal.example.com:6379'
        }
    });
});

// Catch-all for unknown routes
app.use('*', async (req, res) => {
    await delay();
    res.status(404).json({ error: 'Not found' });
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
});

// Rate limiter stats endpoint (internal use)
app.get('/internal/ratelimit-stats', (req, res) => {
    res.json(rateLimiter.getStats());
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Honey Claw Fake API running on port ${PORT} (v1.1.0)`);
    console.log(`Honeypot ID: ${HONEYPOT_ID}`);
    console.log(`Rate limiting: ${rateLimiter.enabled ? 'enabled' : 'disabled'} (${rateLimiter.connPerMin}/min, ${rateLimiter.authPerHour}/hr auth)`);
    console.log(`Input validation: enabled`);
});
