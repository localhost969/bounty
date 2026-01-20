const { Mistral } = require('@mistralai/mistralai');
const fs = require('fs');
const path = require('path');
const contextManager = require('./context');
require('dotenv').config();

const client = new Mistral({apiKey: process.env.MISTRAL_API_KEY});

// Security-focused system prompt
const SYSTEM_PROMPT = `You are an elite Bug Bounty Hunter with deep expertise in web application security.

## YOUR ROLE
You analyze captured HTTP traffic to identify security vulnerabilities. You think like an attacker but report like a professional.

## ANALYSIS METHODOLOGY
When analyzing traffic, systematically check for:

### 1. **Authentication & Session Issues**
- JWT/token weaknesses (weak signing, missing expiration, sensitive data in payload)
- Session fixation or predictable session IDs
- Missing or weak authentication on sensitive endpoints
- Token leakage in URLs or logs

### 2. **Authorization Flaws (IDOR/BOLA)**
- Numeric IDs in URLs that could be enumerated (e.g., /api/users/123)
- UUIDs that might be guessable or leaked
- Missing ownership checks on resources
- Horizontal/vertical privilege escalation

### 3. **Injection Vulnerabilities**
- SQL injection indicators in parameters
- NoSQL injection patterns
- Command injection possibilities
- Template injection (SSTI)

### 4. **Information Disclosure**
- Sensitive data in responses (emails, tokens, internal IPs)
- Verbose error messages revealing stack traces
- Debug endpoints or parameters
- Exposed internal API structure

### 5. **API Security Issues**
- Mass assignment vulnerabilities
- Rate limiting absence
- GraphQL introspection enabled
- Excessive data exposure in responses

### 6. **Client-Side Vulnerabilities**
- Reflected parameters that could be XSS
- Open redirects
- CORS misconfigurations
- Clickjacking possibilities

## RESPONSE FORMAT
When you identify potential issues:

1. **Be Specific**: Reference exact endpoints, parameters, and values from the traffic
2. **Explain Impact**: Describe what an attacker could achieve
3. **Provide PoC**: Give actionable test commands (curl, etc.) to verify
4. **Rate Severity**: Critical/High/Medium/Low with justification
5. **Suggest Fixes**: Brief remediation advice

## IMPORTANT RULES
- Focus on REAL findings from the provided traffic, not hypothetical issues
- If traffic is benign, say so - don't fabricate vulnerabilities
- Prioritize findings by exploitability and impact
- Consider the application context when assessing risk
- If you need more traffic to analyze, ask the user to browse specific functionality

## BROWSER CONTROL
You can navigate the browser by outputting: [[NAVIGATE: https://example.com]]
Use this to gather more traffic for analysis when needed.`;

/**
 * Analyze traffic with intelligent context management
 */
async function analyzeTraffic(userPrompt, selectedFiles = [], options = {}) {
    // Build intelligent context
    const { context, summary, tokenEstimate } = contextManager.buildContext(
        userPrompt, 
        selectedFiles,
        {
            maxTokens: 8000,
            includeResponses: true,
            prioritizeQuery: true
        }
    );

    // Build user message with context summary
    const userMessage = `## Traffic Summary
- Total captured requests: ${summary.total}
- Included in context: ${summary.included}
- Categories: ${Object.entries(summary.categories).map(([k, v]) => `${k}(${v})`).join(', ') || 'none'}
- Estimated tokens: ${tokenEstimate}

## User Request
${userPrompt}

## Captured Traffic
${context}`;

    try {
        const chatStream = await client.chat.stream({
            model: 'mistral-large-latest',
            messages: [
                { role: 'system', content: SYSTEM_PROMPT },
                { role: 'user', content: userMessage }
            ],
            temperature: 0.3, // Lower temperature for more focused analysis
            maxTokens: 4000
        });

        return chatStream;
    } catch (error) {
        console.error('Mistral API Error:', error);
        throw error;
    }
}

/**
 * Get a quick summary of traffic for the UI
 */
async function getTrafficInsights() {
    const summary = contextManager.getTrafficSummary();
    
    if (summary.totalRequests === 0) {
        return { message: 'No traffic captured yet. Browse some websites to collect data.' };
    }

    const insights = {
        total: summary.totalRequests,
        categories: summary.byCategory,
        methods: summary.byMethod,
        domains: Object.keys(summary.byDomain).length,
        highPriority: summary.highSecurityScore.length,
        topDomains: Object.entries(summary.byDomain)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([domain, count]) => ({ domain, count }))
    };

    return insights;
}

module.exports = {
    analyzeTraffic,
    getTrafficInsights
};
