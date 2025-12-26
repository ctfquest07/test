const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const Redis = require('ioredis');
const User = require('../models/User');

// Initialize Redis for realtime subscriptions
// We need a separate connection for subscribing (Redis limitation)
const subscriber = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

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

    // 3. Send initial connection message
    res.write(`data: ${JSON.stringify({ type: 'connected', message: 'Connected to live submission stream' })}\n\n`);

    // 4. Message Handler
    const messageHandler = (channel, message) => {
        if (channel === 'ctf:submissions:live') {
            // Format as SSE data
            res.write(`data: ${message}\n\n`);
        }
    };

    // 5. Subscribe to Redis
    // Note: We might already be subscribed if other clients are connected, 
    // but ‘subscribe’ is idempotent in terms of logic, though subscriber handles it globally.
    // Actually, 'subscriber' is global here. If we add a listener for every request, 
    // we need to make sure we don't multiply-subscribe on the redis level if ioredis doesn't handle it,
    // but ioredis handles multiplexing. We just need to attach the event listener.

    subscriber.subscribe('ctf:submissions:live', (err) => {
        if (err) {
            console.error('Failed to subscribe to submissions channel:', err);
        }
    });

    subscriber.on('message', messageHandler);

    // 6. Cleanup on client disconnect
    req.on('close', () => {
        subscriber.removeListener('message', messageHandler);
    });
});

module.exports = router;
