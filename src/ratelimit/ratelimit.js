/**
 * Honey Claw - Rate Limiter for Node.js Services
 * Simple in-memory per-IP rate limiting with automatic cleanup.
 * 
 * Configuration via environment variables:
 *   RATELIMIT_CONN_PER_MIN     - Max connections per IP per minute (default: 10)
 *   RATELIMIT_AUTH_PER_HOUR    - Max auth attempts per IP per hour (default: 100)
 *   RATELIMIT_CLEANUP_INTERVAL - Cleanup interval in seconds (default: 60)
 *   RATELIMIT_ENABLED          - Enable rate limiting (default: true)
 */

class RateLimiter {
    constructor(options = {}) {
        this.enabled = (process.env.RATELIMIT_ENABLED || 'true').toLowerCase() === 'true';
        this.connPerMin = options.connPerMin || parseInt(process.env.RATELIMIT_CONN_PER_MIN || '10', 10);
        this.authPerHour = options.authPerHour || parseInt(process.env.RATELIMIT_AUTH_PER_HOUR || '100', 10);
        this.cleanupInterval = options.cleanupInterval || parseInt(process.env.RATELIMIT_CLEANUP_INTERVAL || '60', 10);
        this.logCallback = options.logCallback || this._defaultLog.bind(this);
        
        // Counters: Map<ip, timestamp[]>
        this._connCounts = new Map();
        this._authCounts = new Map();
        
        // Stats
        this._blockedConns = 0;
        this._blockedAuths = 0;
        
        // Start cleanup interval
        this._cleanupTimer = setInterval(() => this._cleanup(), this.cleanupInterval * 1000);
    }
    
    _defaultLog(event) {
        event.timestamp = new Date().toISOString();
        console.log(JSON.stringify(event));
    }
    
    /**
     * Check if a connection from IP should be allowed.
     * @param {string} ip - Client IP address
     * @returns {{allowed: boolean, reason?: string}}
     */
    checkConnection(ip) {
        if (!this.enabled) {
            return { allowed: true };
        }
        
        const now = Date.now();
        const minuteAgo = now - 60000;
        
        // Clean old entries
        let timestamps = this._connCounts.get(ip) || [];
        timestamps = timestamps.filter(t => t > minuteAgo);
        
        // Check limit
        if (timestamps.length >= this.connPerMin) {
            this._blockedConns++;
            this.logCallback({
                event: 'rate_limit_connection',
                ip,
                count: timestamps.length,
                limit: this.connPerMin,
                window: '1m',
                total_blocked: this._blockedConns
            });
            this._connCounts.set(ip, timestamps);
            return { 
                allowed: false, 
                reason: `Connection rate limit exceeded (${this.connPerMin}/min)` 
            };
        }
        
        // Record connection
        timestamps.push(now);
        this._connCounts.set(ip, timestamps);
        
        return { allowed: true };
    }
    
    /**
     * Check if an auth attempt from IP should be allowed.
     * @param {string} ip - Client IP address
     * @returns {{allowed: boolean, reason?: string}}
     */
    checkAuth(ip) {
        if (!this.enabled) {
            return { allowed: true };
        }
        
        const now = Date.now();
        const hourAgo = now - 3600000;
        
        // Clean old entries
        let timestamps = this._authCounts.get(ip) || [];
        timestamps = timestamps.filter(t => t > hourAgo);
        
        // Check limit
        if (timestamps.length >= this.authPerHour) {
            this._blockedAuths++;
            this.logCallback({
                event: 'rate_limit_auth',
                ip,
                count: timestamps.length,
                limit: this.authPerHour,
                window: '1h',
                total_blocked: this._blockedAuths
            });
            this._authCounts.set(ip, timestamps);
            return { 
                allowed: false, 
                reason: `Auth rate limit exceeded (${this.authPerHour}/hour)` 
            };
        }
        
        // Record auth attempt
        timestamps.push(now);
        this._authCounts.set(ip, timestamps);
        
        return { allowed: true };
    }
    
    /**
     * Record an auth attempt without checking limits.
     * @param {string} ip - Client IP address
     */
    recordAuth(ip) {
        if (!this.enabled) return;
        
        const timestamps = this._authCounts.get(ip) || [];
        timestamps.push(Date.now());
        this._authCounts.set(ip, timestamps);
    }
    
    /**
     * Get current rate limiter statistics.
     * @returns {object}
     */
    getStats() {
        return {
            enabled: this.enabled,
            config: {
                connPerMin: this.connPerMin,
                authPerHour: this.authPerHour,
                cleanupInterval: this.cleanupInterval
            },
            trackedIps: {
                connections: this._connCounts.size,
                auths: this._authCounts.size
            },
            blocked: {
                connections: this._blockedConns,
                auths: this._blockedAuths
            }
        };
    }
    
    _cleanup() {
        const now = Date.now();
        const minuteAgo = now - 60000;
        const hourAgo = now - 3600000;
        
        // Clean connection counters
        for (const [ip, timestamps] of this._connCounts.entries()) {
            const valid = timestamps.filter(t => t > minuteAgo);
            if (valid.length === 0) {
                this._connCounts.delete(ip);
            } else {
                this._connCounts.set(ip, valid);
            }
        }
        
        // Clean auth counters
        for (const [ip, timestamps] of this._authCounts.entries()) {
            const valid = timestamps.filter(t => t > hourAgo);
            if (valid.length === 0) {
                this._authCounts.delete(ip);
            } else {
                this._authCounts.set(ip, valid);
            }
        }
    }
    
    shutdown() {
        if (this._cleanupTimer) {
            clearInterval(this._cleanupTimer);
            this._cleanupTimer = null;
        }
    }
}

// Singleton instance
let defaultLimiter = null;

function getLimiter(options = {}) {
    if (!defaultLimiter) {
        defaultLimiter = new RateLimiter(options);
    }
    return defaultLimiter;
}

/**
 * Express middleware for rate limiting connections.
 * @param {object} options - RateLimiter options
 * @returns {function} Express middleware
 */
function rateLimitMiddleware(options = {}) {
    const limiter = getLimiter(options);
    
    return (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress || 'unknown';
        const result = limiter.checkConnection(ip);
        
        if (!result.allowed) {
            return res.status(429).json({ 
                error: 'Too Many Requests', 
                message: result.reason,
                retry_after: 60
            });
        }
        
        next();
    };
}

/**
 * Express middleware for rate limiting auth attempts.
 * Call this on auth endpoints.
 * @param {object} options - RateLimiter options
 * @returns {function} Express middleware
 */
function authRateLimitMiddleware(options = {}) {
    const limiter = getLimiter(options);
    
    return (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress || 'unknown';
        const result = limiter.checkAuth(ip);
        
        if (!result.allowed) {
            return res.status(429).json({ 
                error: 'Too Many Requests', 
                message: result.reason,
                retry_after: 3600
            });
        }
        
        next();
    };
}

module.exports = {
    RateLimiter,
    getLimiter,
    rateLimitMiddleware,
    authRateLimitMiddleware
};
