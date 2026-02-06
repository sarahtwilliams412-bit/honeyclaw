/**
 * Log Sanitization Utilities
 * 
 * Prevents sensitive data from leaking into logs.
 * IMPORTANT: IPs are intentionally NOT redacted - they're valuable for honeypot analysis.
 */

// Patterns that indicate sensitive data
const SENSITIVE_PATTERNS = [
  // Passwords and secrets
  /password[=:]\s*\S+/gi,
  /passwd[=:]\s*\S+/gi,
  /secret[=:]\s*\S+/gi,
  /api[_-]?key[=:]\s*\S+/gi,
  /token[=:]\s*\S+/gi,
  /auth[=:]\s*\S+/gi,
  
  // Credit cards (basic pattern)
  /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g,
  
  // API keys (common formats)
  /sk[-_]live[-_][a-zA-Z0-9]{24,}/g,  // Stripe secret keys
  /sk[-_]test[-_][a-zA-Z0-9]{24,}/g,  // Stripe test keys
  /[a-zA-Z0-9]{32,}/g,                 // Generic long tokens (be careful with this)
  
  // Email addresses in unexpected places
  // /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  
  // Private keys
  /-----BEGIN[A-Z ]+PRIVATE KEY-----[\s\S]*?-----END[A-Z ]+PRIVATE KEY-----/g,
];

// Patterns for system paths that shouldn't be logged
const PATH_PATTERNS = [
  /\/Users\/[^\/\s]+/g,           // macOS home dirs
  /\/home\/[^\/\s]+/g,            // Linux home dirs
  /C:\\Users\\[^\\\/\s]+/gi,      // Windows home dirs
];

/**
 * Sanitize a message for logging
 * @param {string} message - Raw message to sanitize
 * @param {Object} options - Options
 * @param {boolean} options.redactPaths - Redact system paths (default: true)
 * @param {boolean} options.truncate - Truncate long messages (default: true)
 * @param {number} options.maxLength - Max length before truncation (default: 500)
 * @returns {string} Sanitized message
 */
function sanitize(message, options = {}) {
  const {
    redactPaths = true,
    truncate = true,
    maxLength = 500,
  } = options;

  if (typeof message !== 'string') {
    // Convert to string safely
    try {
      message = JSON.stringify(message);
    } catch {
      message = String(message);
    }
  }

  let sanitized = message;

  // Redact sensitive patterns
  for (const pattern of SENSITIVE_PATTERNS) {
    sanitized = sanitized.replace(pattern, '[REDACTED]');
  }

  // Redact system paths
  if (redactPaths) {
    for (const pattern of PATH_PATTERNS) {
      sanitized = sanitized.replace(pattern, '[PATH]');
    }
  }

  // Truncate if needed
  if (truncate && sanitized.length > maxLength) {
    sanitized = sanitized.substring(0, maxLength) + '... [truncated]';
  }

  return sanitized;
}

/**
 * Sanitize error for logging
 * Logs message only, not stack trace (which may contain sensitive info)
 * @param {Error} error - Error object
 * @returns {string} Safe error message
 */
function sanitizeError(error) {
  if (!error) return 'Unknown error';
  
  // Only log the message, not the stack
  const message = error.message || String(error);
  return sanitize(message, { redactPaths: true, truncate: true });
}

/**
 * Sanitize user message for logging
 * Used for bot messages - logs command only, not full content
 * @param {string} text - User message text
 * @returns {string} Safe log entry showing command without sensitive content
 */
function sanitizeUserMessage(text) {
  if (!text) return '(no text)';
  
  // If it's a command, log the command name only (not arguments)
  if (text.startsWith('/')) {
    const parts = text.split(/\s+/);
    const command = parts[0];
    const argCount = parts.length - 1;
    
    // Safe commands that can show their first argument
    const safeCommands = ['/deploy', '/status', '/logs', '/help', '/start', '/pricing'];
    
    if (safeCommands.includes(command.toLowerCase())) {
      if (argCount > 0) {
        return `${command} [${argCount} args]`;
      }
      return command;
    }
    
    // For unknown commands, just show the command
    return `${command} [${argCount} args]`;
  }
  
  // Non-command messages - just show length, not content
  // (user might accidentally paste passwords, tokens, etc.)
  return `(message: ${text.length} chars)`;
}

/**
 * Create a safe log object for structured logging
 * @param {Object} data - Data to log
 * @param {string[]} allowedFields - Fields safe to include as-is
 * @returns {Object} Sanitized log object
 */
function sanitizeObject(data, allowedFields = []) {
  if (!data || typeof data !== 'object') {
    return { value: sanitize(String(data)) };
  }

  const result = {};
  
  for (const [key, value] of Object.entries(data)) {
    if (allowedFields.includes(key)) {
      result[key] = value;
    } else {
      // Redact potentially sensitive fields
      const lowerKey = key.toLowerCase();
      if (
        lowerKey.includes('password') ||
        lowerKey.includes('secret') ||
        lowerKey.includes('token') ||
        lowerKey.includes('key') ||
        lowerKey.includes('auth') ||
        lowerKey.includes('credential')
      ) {
        result[key] = '[REDACTED]';
      } else if (typeof value === 'string') {
        result[key] = sanitize(value);
      } else if (typeof value === 'object' && value !== null) {
        result[key] = sanitizeObject(value, allowedFields);
      } else {
        result[key] = value;
      }
    }
  }
  
  return result;
}

module.exports = {
  sanitize,
  sanitizeError,
  sanitizeUserMessage,
  sanitizeObject,
  SENSITIVE_PATTERNS,
};
