const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const browser = require('./browser');
const ai = require('./ai');
const contextManager = require('./context');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const CAPTURED_DIR = path.join(__dirname, '../captured');

// Ensure captured directory exists
if (!fs.existsSync(CAPTURED_DIR)) {
    fs.mkdirSync(CAPTURED_DIR, { recursive: true });
}

app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, '../public')));

// Browser Control
app.post('/api/launch', async (req, res) => {
    try {
        await browser.launchBrowser();
        res.json({ status: 'Browser launched' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/connect', async (req, res) => {
    try {
        await browser.connectToBrowser();
        res.json({ status: 'Connected to external browser' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/close', async (req, res) => {
    try {
        await browser.closeBrowser();
        res.json({ status: 'Browser closed' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/navigate', async (req, res) => {
    const { url } = req.body;
    try {
        await browser.navigateTo(url);
        res.json({ status: `Navigated to ${url}` });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// File Management - Enhanced with metadata
app.get('/api/files', (req, res) => {
    try {
        const files = contextManager.getAllCapturedFiles();
        res.json({ files });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/file/:name', (req, res) => {
    const filePath = path.join(CAPTURED_DIR, req.params.name);
    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
    } else {
        res.status(404).json({ error: 'File not found' });
    }
});

// Clear all captured traffic
app.post('/api/clear', (req, res) => {
    try {
        const files = fs.readdirSync(CAPTURED_DIR).filter(f => f.endsWith('.json'));
        files.forEach(f => fs.unlinkSync(path.join(CAPTURED_DIR, f)));
        res.json({ status: 'Cleared', count: files.length });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Traffic summary/insights
app.get('/api/summary', (req, res) => {
    try {
        const summary = contextManager.getTrafficSummary();
        res.json(summary);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// AI Analysis
app.post('/api/analyze', async (req, res) => {
    const { prompt, files } = req.body;
    
    // Set headers for streaming
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Transfer-Encoding', 'chunked');

    try {
        const stream = await ai.analyzeTraffic(prompt, files);
        
        for await (const chunk of stream) {
            if (chunk.data.choices[0].delta.content) {
                res.write(chunk.data.choices[0].delta.content);
            }
        }
        res.end();
    } catch (e) {
        console.error(e);
        res.write(`\nError: ${e.message}`);
        res.end();
    }
});

// Auto-spawn Chrome on startup
let chromeProcess;

function startChrome() {
    console.log('Starting Chrome with remote debugging...');
    // If a previous chrome process exists, try to kill it first
    if (chromeProcess) {
        try { chromeProcess.kill(); } catch (e) { /* ignore */ }
    }

    chromeProcess = spawn('google-chrome', [
        '--remote-debugging-port=9222',
        '--user-data-dir=/tmp/chrome-debug'
    ], {
        stdio: 'ignore',
        detached: true
    });
    
    chromeProcess.unref();
    console.log('Chrome process started.');
}

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    
    // Start Chrome after a short delay to ensure it's ready
    setTimeout(() => {
        startChrome();
    }, 500);
});

// Graceful shutdown for manual stops
process.on('SIGINT', () => {
    console.log('Shutting down...');
    if (chromeProcess) {
        chromeProcess.kill();
    }
    process.exit(0);
});

// Nodemon restart handler (SIGUSR2)
process.once('SIGUSR2', () => {
    console.log('SIGUSR2 received, shutting down Chrome for restart...');
    if (chromeProcess) {
        chromeProcess.kill();
    }
    // forward the signal to let nodemon restart the process
    process.kill(process.pid, 'SIGUSR2');
});

// SIGTERM handling
process.on('SIGTERM', () => {
    console.log('SIGTERM received, exiting...');
    if (chromeProcess) chromeProcess.kill();
    process.exit(0);
});
