const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const Redis = require('ioredis');
const User = require('../models/User');

// Initialize Redis for realtime subscriptions
// We need a separate connection for subscribing (Redis limitation)
const subscriber = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

// Track active connections
let activeConnections = 0;

// Set up the subscriber once globally
subscriber.on('error', (err) => {
    console.error('Redis Subscriber Error:', err);
});

subscriber.on('ready', () => {
    console.log('Redis Subscriber Ready');
});

// Subscribe to the channel once when the module loads
subscriber.subscribe('ctf:submissions:live', (err, count) => {
    if (err) {
        console.error('Failed to subscribe to ctf:submissions:live:', err);
    } else {
        console.log(`Subscribed to ctf:submissions:live. Active subscriptions: ${count}`);
    }
});

router.get('/', async (req, res) => {
    // 1. Authentication (via query param since EventSource doesn't support headers)
    const token = req.query.token;

    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id);

        if (!user || user.role !== 'admin') {
            return res.status(403).json({ message: 'Not authorized' });
        }
    } catch (err) {
        console.error('SSE Auth error:', err);
        return res.status(401).json({ message: 'Invalid token' });
    }

    // 2. Setup SSE Headers with CORS support
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no'); // Important for Nginx/proxy
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    
    // Write status code
    res.status(200);

    activeConnections++;
    console.log(`[SSE] New connection. Active: ${activeConnections}, User: ${user.username}`);

    // 3. Send initial connection message and flush
    res.write(`data: ${JSON.stringify({ type: 'connected', message: 'Connected to live submission stream' })}\n\n`);
    
    // Flush the response to establish connection immediately
    if (res.flush) res.flush();

    // 4. Message Handler for this specific connection
    const messageHandler = (channel, message) => {
        if (channel === 'ctf:submissions:live') {
            try {
                // Check if connection is still alive
                if (res.writableEnded || res.finished) {
                    return;
                }
                // Format as SSE data
                res.write(`data: ${message}\n\n`);
                // Flush to ensure immediate delivery
                if (res.flush) res.flush();
            } catch (err) {
                console.error('[SSE] Error writing message:', err);
                // Clean up on write error
                subscriber.removeListener('message', messageHandler);
            }
        }
    };

    // 5. Attach message handler for this connection
    subscriber.on('message', messageHandler);

    // Send heartbeat every 15 seconds to keep connection alive
    const heartbeatInterval = setInterval(() => {
        try {
            // Check if connection is still alive
            if (res.writableEnded || res.finished) {
                clearInterval(heartbeatInterval);
                return;
            }
            res.write(`:heartbeat\n\n`);
            if (res.flush) res.flush();
        } catch (err) {
            console.error('[SSE] Heartbeat error:', err);
            clearInterval(heartbeatInterval);
        }
    }, 15000);

    // 6. Cleanup on client disconnect
    req.on('close', () => {
        subscriber.removeListener('message', messageHandler);
        clearInterval(heartbeatInterval);
        activeConnections--;
        console.log(`[SSE] Connection closed. Active: ${activeConnections}`);
    });
});

module.exports = router;
