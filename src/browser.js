const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const { shouldCapture, truncateBody, generateFilename, categorizeUrl, extractSecurityHeaders, generateRequestHash } = require('./utils');

let browser;
let page;

const CAPTURED_DIR = path.join(__dirname, '../captured');

// Track captured requests to avoid duplicates
const capturedHashes = new Set();

// Ensure captured directory exists
if (!fs.existsSync(CAPTURED_DIR)) {
    fs.mkdirSync(CAPTURED_DIR, { recursive: true });
}

// Helper to setup listeners on a page
async function setupPageListeners(targetPage) {
    targetPage.on('response', async (response) => {
        const request = response.request();
        const url = request.url();
        const method = request.method();
        const resourceType = request.resourceType();
        const status = response.status();

        const captureResult = shouldCapture(url, resourceType);
        
        if (captureResult.capture) {
            try {
                // Generate hash for deduplication
                const postData = request.postData();
                const hash = generateRequestHash(method, url, postData);
                
                // Skip if we've seen this exact request recently
                if (capturedHashes.has(hash)) {
                    return;
                }
                capturedHashes.add(hash);
                
                // Clean up old hashes (keep last 1000)
                if (capturedHashes.size > 1000) {
                    const arr = Array.from(capturedHashes);
                    capturedHashes.clear();
                    arr.slice(-500).forEach(h => capturedHashes.add(h));
                }

                let responseBody;
                try {
                    responseBody = await response.text();
                } catch (e) {
                    responseBody = '[Could not read response body]';
                }

                // Get content type
                const contentType = response.headers()['content-type'] || 'unknown';
                
                // Categorize the request
                const category = categorizeUrl(url, method, postData);
                
                // Calculate response size
                const responseSize = responseBody ? responseBody.length : 0;

                const captureData = {
                    // Core request info
                    url,
                    method,
                    status,
                    contentType,
                    responseSize,
                    
                    // Categorization
                    category,
                    priority: captureResult.priority,
                    hash,
                    
                    // Headers (security-relevant only)
                    requestHeaders: extractSecurityHeaders(request.headers()),
                    responseHeaders: extractSecurityHeaders(response.headers()),
                    
                    // Body data
                    postData: postData ? truncateBody(postData, 2000) : null,
                    responseBody: truncateBody(responseBody, 5000),
                    
                    // Metadata
                    timestamp: new Date().toISOString(),
                    resourceType
                };

                const filename = generateFilename(method, url, status);
                fs.writeFileSync(path.join(CAPTURED_DIR, filename), JSON.stringify(captureData, null, 2));
                
                // Log with color based on priority
                const priorityColor = captureResult.priority === 'high' ? '\x1b[32m' : 
                                      captureResult.priority === 'medium' ? '\x1b[33m' : '\x1b[90m';
                console.log(`${priorityColor}[${captureResult.priority.toUpperCase()}]\x1b[0m ${method} ${status} ${url.substring(0, 80)}${url.length > 80 ? '...' : ''}`);
                
            } catch (err) {
                // Silent fail for common issues
                if (!err.message.includes('Target closed')) {
                    console.error('Capture error:', err.message);
                }
            }
        }
    });
    
    console.log('Traffic capture listeners attached.');
}

async function launchBrowser() {
    if (browser) return;

    browser = await puppeteer.launch({
        headless: false,
        defaultViewport: null,
        args: ['--start-maximized', '--no-sandbox', '--disable-setuid-sandbox'],
        userDataDir: path.join(__dirname, '../user_data')
    });

    page = await browser.newPage();
    await setupPageListeners(page);
    console.log('Browser launched and capturing traffic...');
}

async function connectToBrowser(port = 9222) {
    try {
        // Fetch the WebSocket Debugger URL
        const response = await axios.get(`http://127.0.0.1:${port}/json/version`);
        const webSocketDebuggerUrl = response.data.webSocketDebuggerUrl;

        if (!webSocketDebuggerUrl) {
            throw new Error('Could not find webSocketDebuggerUrl. Is Chrome running with --remote-debugging-port=9222?');
        }

        browser = await puppeteer.connect({
            browserWSEndpoint: webSocketDebuggerUrl,
            defaultViewport: null
        });

        // Get all open pages and attach listeners
        const pages = await browser.pages();
        if (pages.length > 0) {
            page = pages[0]; // Control the first page
            // Attach to all existing pages
            for (const p of pages) {
                await setupPageListeners(p);
            }
        } else {
            page = await browser.newPage();
            await setupPageListeners(page);
        }

        // Listen for new pages (tabs)
        browser.on('targetcreated', async (target) => {
            if (target.type() === 'page') {
                const newPage = await target.page();
                if (newPage) await setupPageListeners(newPage);
            }
        });

        console.log(`Connected to external browser at ${webSocketDebuggerUrl}`);
        return true;
    } catch (e) {
        console.error('Connection failed:', e.message);
        if (e.message.includes('ECONNREFUSED')) {
            throw new Error('Connection refused. Make sure Chrome is running with --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-debug');
        }
        throw e;
    }
}

async function closeBrowser() {
    if (browser) {
        browser.disconnect();
        browser = null;
        page = null;
        console.log('Disconnected from browser.');
    }
}

async function navigateTo(url) {
    if (page) {
        await page.goto(url, { waitUntil: 'domcontentloaded' });
    }
}

module.exports = {
    launchBrowser,
    connectToBrowser,
    closeBrowser,
    navigateTo
};
