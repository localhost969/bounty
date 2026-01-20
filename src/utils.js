const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

// List of extensions to ignore
const IGNORED_EXTENSIONS = [
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', 
    '.ttf', '.eot', '.mp4', '.webm', '.mp3', '.wav', '.map', '.wasm'
];

// List of domains/keywords to ignore (trackers, ads, etc.)
const IGNORED_DOMAINS = [
    'google-analytics.com', 'doubleclick.net', 'facebook.com/tr', 'googletagmanager.com', 
    'hotjar.com', 'newrelic.com', 'sentry.io', 'segment.io', 'mixpanel.com', 
    'amplitude.com', 'clarity.ms', 'cloudflareinsights.com', 'googleads.g.doubleclick.net',
    'googlesyndication.com', 'adservice.google.com', 'analytics.', 'tracking.'
];

// Paths to always ignore
const IGNORED_PATHS = [
    '/favicon.ico', '/robots.txt', '/sitemap.xml', '/manifest.json', 
    '/.well-known/', '/sw.js', '/service-worker.js'
];

// Security-interesting keywords (boost capture priority)
const SECURITY_KEYWORDS = [
    'api', 'auth', 'login', 'logout', 'user', 'admin', 'token', 'session',
    'password', 'account', 'profile', 'settings', 'config', 'private', 'secret',
    'upload', 'download', 'file', 'document', 'export', 'import', 'payment',
    'checkout', 'order', 'invoice', 'graphql', 'webhook', 'callback'
];

/**
 * Determines if a request should be captured based on URL and resource type.
 * Returns { capture: boolean, priority: 'high' | 'medium' | 'low' }
 */
function shouldCapture(requestUrl, resourceType) {
    try {
        const parsedUrl = new URL(requestUrl);
        const pathname = parsedUrl.pathname || '';
        const hostname = parsedUrl.hostname || '';
        const fullUrl = requestUrl.toLowerCase();

        // Ignore by resource type
        if (['image', 'stylesheet', 'font', 'media', 'manifest', 'other'].includes(resourceType)) {
            return { capture: false };
        }

        // Ignore by extension
        if (IGNORED_EXTENSIONS.some(ext => pathname.toLowerCase().endsWith(ext))) {
            return { capture: false };
        }

        // Ignore by domain
        if (IGNORED_DOMAINS.some(domain => hostname.includes(domain))) {
            return { capture: false };
        }

        // Ignore specific paths
        if (IGNORED_PATHS.some(p => pathname.startsWith(p) || pathname === p)) {
            return { capture: false };
        }

        // Determine priority based on security interest
        let priority = 'low';
        
        // XHR and Fetch are high priority
        if (resourceType === 'xhr' || resourceType === 'fetch') {
            priority = 'medium';
        }

        // Boost priority for security-interesting URLs
        if (SECURITY_KEYWORDS.some(kw => fullUrl.includes(kw))) {
            priority = 'high';
        }

        // Boost priority for API-like paths
        if (/\/(api|v\d|graphql)\//i.test(pathname)) {
            priority = 'high';
        }

        return { capture: true, priority };
    } catch (e) {
        return { capture: false };
    }
}

/**
 * Truncates and cleans response body intelligently
 * @param {object|string} body 
 * @param {number} maxLength - max string length
 * @returns {object|string}
 */
function truncateBody(body, maxLength = 5000) {
    if (!body) return body;

    let jsonBody = body;
    let isJson = false;
    
    if (typeof body === 'string') {
        // Skip HTML pages (usually not interesting for API analysis)
        if (body.trim().startsWith('<!DOCTYPE') || body.trim().startsWith('<html')) {
            return '[HTML Page - Not Captured]';
        }
        
        try {
            jsonBody = JSON.parse(body);
            isJson = true;
        } catch (e) {
            // Not JSON, truncate string
            if (body.length > maxLength) {
                return body.substring(0, maxLength) + `\n...[TRUNCATED - ${body.length - maxLength} more chars]`;
            }
            return body;
        }
    } else {
        isJson = true;
    }

    // Smart array truncation
    function traverse(obj, depth = 0) {
        if (depth > 10) return '[MAX DEPTH]';
        
        if (Array.isArray(obj)) {
            if (obj.length > 3) {
                const truncated = obj.slice(0, 3).map(item => traverse(item, depth + 1));
                truncated.push({ _truncated: `${obj.length - 3} more items` });
                return truncated;
            }
            return obj.map(item => traverse(item, depth + 1));
        } else if (typeof obj === 'object' && obj !== null) {
            const newObj = {};
            const keys = Object.keys(obj);
            
            // Limit object keys if too many
            const keysToProcess = keys.length > 20 ? keys.slice(0, 20) : keys;
            
            for (const key of keysToProcess) {
                // Skip large base64 or binary-looking data
                const value = obj[key];
                if (typeof value === 'string' && value.length > 1000) {
                    if (/^[A-Za-z0-9+/=]{100,}$/.test(value)) {
                        newObj[key] = `[BASE64 DATA - ${value.length} chars]`;
                        continue;
                    }
                }
                newObj[key] = traverse(value, depth + 1);
            }
            
            if (keys.length > 20) {
                newObj._truncatedKeys = `${keys.length - 20} more keys`;
            }
            
            return newObj;
        } else if (typeof obj === 'string' && obj.length > 500) {
            return obj.substring(0, 500) + '...[truncated]';
        }
        return obj;
    }

    const result = traverse(jsonBody);
    
    // Final size check
    const resultStr = JSON.stringify(result);
    if (resultStr.length > maxLength) {
        return resultStr.substring(0, maxLength) + '\n...[TRUNCATED]';
    }
    
    return isJson ? result : resultStr;
}

/**
 * Categorize request based on URL patterns
 */
function categorizeUrl(requestUrl, method, postData) {
    const urlLower = requestUrl.toLowerCase();
    const postLower = (postData || '').toLowerCase();
    
    const categories = {
        auth: ['login', 'logout', 'auth', 'token', 'session', 'oauth', 'signin', 'signup', 'register', 'password', 'jwt'],
        api: ['api/', '/v1/', '/v2/', '/v3/', 'graphql', 'rest'],
        user: ['user', 'profile', 'account', 'me/', '/self', 'member', 'customer'],
        admin: ['admin', 'dashboard', 'manage', 'settings', 'config', 'control-panel'],
        data: ['list', 'search', 'filter', 'query', 'export', 'report'],
        payment: ['payment', 'checkout', 'cart', 'order', 'invoice', 'billing', 'subscription', 'stripe', 'paypal'],
        upload: ['upload', 'file', 'image', 'document', 'attachment', 'media'],
        webhook: ['webhook', 'callback', 'hook', 'notify']
    };
    
    for (const [category, keywords] of Object.entries(categories)) {
        if (keywords.some(kw => urlLower.includes(kw) || postLower.includes(kw))) {
            return category;
        }
    }
    
    // Method-based fallback
    if (method === 'POST' || method === 'PUT' || method === 'PATCH') return 'mutation';
    if (method === 'DELETE') return 'delete';
    
    return 'other';
}

/**
 * Generates a descriptive filename for a captured request.
 */
function generateFilename(method, requestUrl, status) {
    try {
        const parsedUrl = new URL(requestUrl);
        const timestamp = Date.now();
        
        // Extract meaningful path segment
        const pathParts = parsedUrl.pathname.split('/').filter(Boolean);
        const meaningfulPath = pathParts.slice(-2).join('_') || 'root';
        const safePath = meaningfulPath.replace(/[^a-zA-Z0-9_-]/g, '').substring(0, 40);
        
        // Include domain hint
        const domainHint = parsedUrl.hostname.split('.').slice(-2, -1)[0] || 'unknown';
        
        // Status indicator
        const statusHint = status >= 400 ? `_ERR${status}` : '';
        
        return `${timestamp}_${method}_${domainHint}_${safePath}${statusHint}.json`;
    } catch (e) {
        return `${Date.now()}_${method}_unknown.json`;
    }
}

/**
 * Extract security-relevant metadata from headers
 */
function extractSecurityHeaders(headers) {
    const securityHeaders = {};
    const interestingHeaders = [
        'authorization', 'cookie', 'set-cookie', 'x-csrf-token', 'x-xsrf-token',
        'x-api-key', 'x-auth-token', 'x-access-token', 'x-request-id', 'x-correlation-id',
        'www-authenticate', 'x-powered-by', 'server', 'x-frame-options', 
        'content-security-policy', 'x-content-type-options', 'access-control-allow-origin'
    ];
    
    for (const [key, value] of Object.entries(headers || {})) {
        const keyLower = key.toLowerCase();
        if (interestingHeaders.some(h => keyLower.includes(h))) {
            // Mask sensitive values but keep structure
            if (keyLower === 'authorization' || keyLower === 'cookie') {
                securityHeaders[key] = maskSensitiveValue(value);
            } else {
                securityHeaders[key] = value;
            }
        }
    }
    
    return securityHeaders;
}

/**
 * Mask sensitive values while preserving structure
 */
function maskSensitiveValue(value) {
    if (!value) return value;
    
    // Show first and last few chars
    if (value.length > 20) {
        return value.substring(0, 10) + '...[MASKED]...' + value.substring(value.length - 5);
    }
    return value.substring(0, 3) + '...[MASKED]';
}

/**
 * Generate a hash for deduplication
 */
function generateRequestHash(method, url, postData) {
    const normalizedUrl = url.split('?')[0]; // Remove query params for similarity
    const content = `${method}:${normalizedUrl}:${postData || ''}`;
    return crypto.createHash('md5').update(content).digest('hex').substring(0, 12);
}

module.exports = {
    shouldCapture,
    truncateBody,
    generateFilename,
    categorizeUrl,
    extractSecurityHeaders,
    maskSensitiveValue,
    generateRequestHash,
    SECURITY_KEYWORDS,
    IGNORED_DOMAINS
};
   