/**
 * Intelligent Context Manager for Bug Bounty AI Assistant
 * 
 * This module handles smart selection of relevant traffic data to send to LLM,
 * avoiding token waste by filtering, deduplicating, and prioritizing requests.
 */

const fs = require('fs');
const path = require('path');

const CAPTURED_DIR = path.join(__dirname, '../captured');

// Token budget (approximate - Mistral large context is ~32k tokens, we use ~8k for context)
const MAX_CONTEXT_TOKENS = 8000;
const AVG_CHARS_PER_TOKEN = 4;
const MAX_CONTEXT_CHARS = MAX_CONTEXT_TOKENS * AVG_CHARS_PER_TOKEN;

// Priority scores for different request types
const PRIORITY_SCORES = {
    auth: 100,        // Authentication endpoints
    api: 80,          // API calls
    graphql: 90,      // GraphQL queries
    data: 70,         // Data fetching
    form: 75,         // Form submissions
    user: 85,         // User-related endpoints
    admin: 95,        // Admin endpoints
    upload: 80,       // File uploads
    payment: 95,      // Payment endpoints
    default: 50
};

// Keywords for categorization
const CATEGORY_KEYWORDS = {
    auth: ['login', 'logout', 'auth', 'token', 'session', 'oauth', 'signin', 'signup', 'register', 'password', 'jwt', 'bearer'],
    api: ['api', 'v1', 'v2', 'v3', 'graphql', 'rest', 'endpoint'],
    user: ['user', 'profile', 'account', 'me', 'self', 'member', 'customer'],
    admin: ['admin', 'dashboard', 'manage', 'settings', 'config', 'control'],
    data: ['data', 'list', 'get', 'fetch', 'query', 'search', 'filter'],
    payment: ['payment', 'checkout', 'cart', 'order', 'invoice', 'billing', 'subscription'],
    upload: ['upload', 'file', 'image', 'document', 'attachment'],
    form: ['submit', 'create', 'update', 'delete', 'post', 'put', 'patch']
};

// Security-interesting patterns
const SECURITY_PATTERNS = {
    idor: /\/(\d+|[a-f0-9-]{36}|[a-z0-9]{24})\/?(\?|$)/i,  // IDs in URLs
    sensitiveParams: /(password|token|secret|key|api_key|auth|session|credit|ssn|email)/i,
    fileAccess: /\/(files?|documents?|uploads?|attachments?)\//i,
    userContext: /\/(users?|profiles?|accounts?|me|self)\//i,
    adminContext: /\/(admin|manage|dashboard|control)\//i,
    dataExport: /\/(export|download|report|backup)\//i
};

/**
 * Load and parse a captured traffic file
 */
function loadCapturedFile(filename) {
    try {
        const filePath = path.join(CAPTURED_DIR, filename);
        const content = fs.readFileSync(filePath, 'utf8');
        const data = JSON.parse(content);
        data._filename = filename;
        return data;
    } catch (e) {
        console.error(`Error loading ${filename}:`, e.message);
        return null;
    }
}

/**
 * Get all captured files with metadata
 */
function getAllCapturedFiles() {
    try {
        const files = fs.readdirSync(CAPTURED_DIR)
            .filter(f => f.endsWith('.json'))
            .map(filename => {
                const data = loadCapturedFile(filename);
                if (!data) return null;
                
                const stats = fs.statSync(path.join(CAPTURED_DIR, filename));
                return {
                    filename,
                    url: data.url,
                    method: data.method,
                    status: data.status,
                    category: data.category || categorizeRequest(data),
                    securityScore: data.securityScore || calculateSecurityScore(data),
                    contentType: data.contentType,
                    responseSize: data.responseSize,
                    timestamp: data.timestamp,
                    mtime: stats.mtime
                };
            })
            .filter(Boolean)
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        
        return files;
    } catch (e) {
        console.error('Error reading captured directory:', e.message);
        return [];
    }
}

/**
 * Categorize a request based on URL and content
 */
function categorizeRequest(data) {
    const url = (data.url || '').toLowerCase();
    const postData = (data.postData || '').toLowerCase();
    
    for (const [category, keywords] of Object.entries(CATEGORY_KEYWORDS)) {
        if (keywords.some(kw => url.includes(kw) || postData.includes(kw))) {
            return category;
        }
    }
    
    return 'other';
}

/**
 * Calculate security interest score for a request
 */
function calculateSecurityScore(data) {
    let score = PRIORITY_SCORES[data.category] || PRIORITY_SCORES.default;
    const url = data.url || '';
    const postData = data.postData || '';
    const responseBody = typeof data.responseBody === 'string' ? data.responseBody : JSON.stringify(data.responseBody || '');
    
    // Boost for security-interesting patterns
    if (SECURITY_PATTERNS.idor.test(url)) score += 20;
    if (SECURITY_PATTERNS.sensitiveParams.test(url + postData)) score += 25;
    if (SECURITY_PATTERNS.fileAccess.test(url)) score += 15;
    if (SECURITY_PATTERNS.userContext.test(url)) score += 15;
    if (SECURITY_PATTERNS.adminContext.test(url)) score += 20;
    if (SECURITY_PATTERNS.dataExport.test(url)) score += 15;
    
    // Boost for methods that modify data
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(data.method)) score += 10;
    
    // Boost for responses containing sensitive-looking data
    if (/(email|password|token|secret|key|credit|ssn)/i.test(responseBody)) score += 15;
    
    // Boost for error responses (might reveal info)
    if (data.status >= 400 && data.status < 500) score += 10;
    if (data.status >= 500) score += 5;
    
    return Math.min(score, 200); // Cap at 200
}

/**
 * Calculate relevance score based on user query
 */
function calculateQueryRelevance(data, query) {
    if (!query) return 0;
    
    const queryLower = query.toLowerCase();
    const queryTerms = queryLower.split(/\s+/).filter(t => t.length > 2);
    
    const searchableText = [
        data.url,
        data.method,
        data.postData,
        typeof data.responseBody === 'string' ? data.responseBody : JSON.stringify(data.responseBody || '')
    ].join(' ').toLowerCase();
    
    let relevance = 0;
    
    // Direct term matches
    for (const term of queryTerms) {
        if (searchableText.includes(term)) {
            relevance += 20;
        }
    }
    
    // Security keyword matches
    const securityKeywords = ['idor', 'xss', 'sqli', 'injection', 'auth', 'bypass', 'token', 'session', 'cookie', 'admin', 'user', 'api', 'endpoint'];
    for (const kw of securityKeywords) {
        if (queryLower.includes(kw) && searchableText.includes(kw)) {
            relevance += 15;
        }
    }
    
    return relevance;
}

/**
 * Deduplicate similar requests (same endpoint, different params)
 */
function deduplicateRequests(requests) {
    const seen = new Map();
    
    return requests.filter(req => {
        // Create a signature based on method + base URL path
        const urlObj = new URL(req.url);
        const signature = `${req.method}:${urlObj.hostname}${urlObj.pathname}`;
        
        if (seen.has(signature)) {
            const existing = seen.get(signature);
            // Keep the one with higher security score
            if (req.securityScore > existing.securityScore) {
                seen.set(signature, req);
                return true;
            }
            return false;
        }
        
        seen.set(signature, req);
        return true;
    });
}

/**
 * Format request data for LLM context (compact but useful)
 */
function formatForContext(data, includeResponse = true) {
    const lines = [];
    lines.push(`## ${data.method} ${data.url}`);
    lines.push(`Status: ${data.status || 'N/A'} | Category: ${data.category || 'unknown'} | Security Score: ${data.securityScore || 'N/A'}`);
    
    // Include relevant headers
    const interestingHeaders = ['authorization', 'cookie', 'content-type', 'x-csrf-token', 'x-api-key'];
    const reqHeaders = data.requestHeaders || {};
    const relevantHeaders = Object.entries(reqHeaders)
        .filter(([k]) => interestingHeaders.some(h => k.toLowerCase().includes(h)))
        .map(([k, v]) => `  ${k}: ${v.substring(0, 100)}${v.length > 100 ? '...' : ''}`);
    
    if (relevantHeaders.length > 0) {
        lines.push('Request Headers:');
        lines.push(...relevantHeaders);
    }
    
    if (data.postData) {
        lines.push('Request Body:');
        lines.push('```json');
        lines.push(truncateForContext(data.postData, 500));
        lines.push('```');
    }
    
    if (includeResponse && data.responseBody) {
        lines.push('Response:');
        lines.push('```json');
        lines.push(truncateForContext(
            typeof data.responseBody === 'string' ? data.responseBody : JSON.stringify(data.responseBody, null, 2),
            1000
        ));
        lines.push('```');
    }
    
    lines.push('---');
    return lines.join('\n');
}

/**
 * Truncate text for context while keeping it readable
 */
function truncateForContext(text, maxLength) {
    if (!text) return '';
    // Convert to string if needed
    const textStr = typeof text === 'string' ? text : JSON.stringify(text, null, 2);
    if (textStr.length <= maxLength) return textStr;
    return textStr.substring(0, maxLength) + '\n... [truncated]';
}

/**
 * Build intelligent context for LLM based on query and available data
 */
function buildContext(userQuery, selectedFiles = [], options = {}) {
    const {
        maxTokens = MAX_CONTEXT_TOKENS,
        includeResponses = true,
        prioritizeQuery = true
    } = options;
    
    const maxChars = maxTokens * AVG_CHARS_PER_TOKEN;
    let requests = [];
    
    if (selectedFiles.length > 0) {
        // User selected specific files
        requests = selectedFiles.map(f => loadCapturedFile(f)).filter(Boolean);
    } else {
        // Auto-select based on relevance
        const allFiles = getAllCapturedFiles();
        requests = allFiles.map(meta => loadCapturedFile(meta.filename)).filter(Boolean);
    }
    
    // Enrich with scores
    requests = requests.map(req => ({
        ...req,
        category: req.category || categorizeRequest(req),
        securityScore: req.securityScore || calculateSecurityScore(req),
        queryRelevance: prioritizeQuery ? calculateQueryRelevance(req, userQuery) : 0
    }));
    
    // Sort by combined relevance (query relevance + security score)
    requests.sort((a, b) => {
        const scoreA = a.queryRelevance + a.securityScore;
        const scoreB = b.queryRelevance + b.securityScore;
        return scoreB - scoreA;
    });
    
    // Deduplicate
    requests = deduplicateRequests(requests);
    
    // Build context within token budget
    let context = '';
    let includedCount = 0;
    const summary = { total: requests.length, included: 0, categories: {} };
    
    for (const req of requests) {
        const formatted = formatForContext(req, includeResponses);
        
        if (context.length + formatted.length > maxChars) {
            // Try without response body if over budget
            if (includeResponses) {
                const shortFormatted = formatForContext(req, false);
                if (context.length + shortFormatted.length <= maxChars) {
                    context += shortFormatted + '\n';
                    includedCount++;
                    summary.categories[req.category] = (summary.categories[req.category] || 0) + 1;
                }
            }
            continue;
        }
        
        context += formatted + '\n';
        includedCount++;
        summary.categories[req.category] = (summary.categories[req.category] || 0) + 1;
    }
    
    summary.included = includedCount;
    
    // Add context header
    const header = `# Captured Traffic Context
**Total Requests Available:** ${summary.total}
**Included in Context:** ${summary.included}
**Categories:** ${Object.entries(summary.categories).map(([k, v]) => `${k}(${v})`).join(', ')}

`;
    
    return {
        context: header + context,
        summary,
        tokenEstimate: Math.ceil((header + context).length / AVG_CHARS_PER_TOKEN)
    };
}

/**
 * Get traffic summary for a domain/session
 */
function getTrafficSummary() {
    const files = getAllCapturedFiles();
    
    const summary = {
        totalRequests: files.length,
        byCategory: {},
        byMethod: {},
        byDomain: {},
        highSecurityScore: [],
        recentRequests: files.slice(0, 10)
    };
    
    for (const file of files) {
        // By category
        summary.byCategory[file.category] = (summary.byCategory[file.category] || 0) + 1;
        
        // By method
        summary.byMethod[file.method] = (summary.byMethod[file.method] || 0) + 1;
        
        // By domain
        try {
            const domain = new URL(file.url).hostname;
            summary.byDomain[domain] = (summary.byDomain[domain] || 0) + 1;
        } catch (e) {}
        
        // High security score
        if (file.securityScore >= 80) {
            summary.highSecurityScore.push(file);
        }
    }
    
    return summary;
}

module.exports = {
    loadCapturedFile,
    getAllCapturedFiles,
    categorizeRequest,
    calculateSecurityScore,
    buildContext,
    getTrafficSummary,
    formatForContext,
    CATEGORY_KEYWORDS,
    SECURITY_PATTERNS
};
