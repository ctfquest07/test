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
        return res.status(401).json({ message: 'Invalid token' });
    }

    // 2. Setup SSE Headers
    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no' // Important for Nginx
    });

    activeConnections++;
    console.log(`New SSE connection. Active connections: ${activeConnections}`);

    // 3. Send initial connection message
    res.write(`data: ${JSON.stringify({ type: 'connected', message: 'Connected to live submission stream' })}\n\n`);

    // 4. Message Handler for this specific connection
    const messageHandler = (channel, message) => {
        if (channel === 'ctf:submissions:live') {
            try {
                // Format as SSE data
                res.write(`data: ${message}\n\n`);
            } catch (err) {
                console.error('Error writing SSE message:', err);
            }
        }
    };

    // 5. Attach message handler for this connection
    subscriber.on('message', messageHandler);

    // Send heartbeat every 30 seconds to keep connection alive
    const heartbeatInterval = setInterval(() => {
        try {
            res.write(`:heartbeat\n\n`);
        } catch (err) {
            clearInterval(heartbeatInterval);
        }
    }, 30000);

    // 6. Cleanup on client disconnect
    req.on('close', () => {
        subscriber.removeListener('message', messageHandler);
        clearInterval(heartbeatInterval);
        activeConnections--;
        console.log(`SSE connection closed. Active connections: ${activeConnections}`);
    });
});

module.exports = router;
