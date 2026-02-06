/**
 * Honey Claw - Fake API Honeypot Server
 * 
 * Medium-interaction API honeypot that simulates a REST API
 * and logs all interactions for threat detection.
 */

const express = require('express');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

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

// Request logging middleware
app.use((req, res, next) => {
    const event = {
        timestamp: new Date().toISOString(),
        honeypot_id: HONEYPOT_ID,
        template: 'fake-api',
        request_id: uuidv4(),
        source: {
            ip: req.ip || req.connection.remoteAddress,
            port: req.connection.remotePort
        },
        request: {
            method: req.method,
            path: req.path,
            query: req.query,
            headers: sanitizeHeaders(req.headers),
            body: req.body
        },
        auth: extractAuth(req),
        detection: detectThreats(req)
    };
    
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
        auth.header = req.headers.authorization;
        
        if (req.headers.authorization.startsWith('Bearer ')) {
            auth.type = 'bearer';
            auth.token = req.headers.authorization.slice(7);
        } else if (req.headers.authorization.startsWith('Basic ')) {
            auth.type = 'basic';
            try {
                const decoded = Buffer.from(req.headers.authorization.slice(6), 'base64').toString();
                const [user, pass] = decoded.split(':');
                auth.username = user;
                auth.password = pass;
            } catch (e) {
                auth.decode_error = true;
            }
        }
    }
    
    if (req.headers['x-api-key']) {
        auth.api_key = req.headers['x-api-key'];
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
            sanitized[header] = headers[header];
        }
    }
    return sanitized;
}

function appendLog(event) {
    try {
        fs.appendFileSync(LOG_FILE, JSON.stringify(event) + '\n');
    } catch (e) {
        console.error('Failed to write log:', e.message);
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
    await delay();
    const { username, password } = req.body;
    
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

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Honey Claw Fake API running on port ${PORT}`);
    console.log(`Honeypot ID: ${HONEYPOT_ID}`);
});
