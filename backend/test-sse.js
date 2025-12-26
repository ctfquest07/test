#!/usr/bin/env node

// Test script for SSE endpoint
const Redis = require('ioredis');

const redisClient = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

console.log('Testing Redis publish to ctf:submissions:live channel...\n');

const testSubmission = {
    user: 'testuser',
    email: 'test@example.com',
    flag: 'CTF{test_flag_123}',
    points: 100,
    submittedAt: new Date().toISOString(),
    ip: '127.0.0.1',
    challenge: 'Test Challenge'
};

redisClient.publish('ctf:submissions:live', JSON.stringify(testSubmission))
    .then((numSubscribers) => {
        console.log(`✓ Published test submission to ${numSubscribers} subscriber(s)`);
        console.log('Test data:', testSubmission);
        
        setTimeout(() => {
            console.log('\nTest complete. Check the live monitor to see if the submission appears.');
            process.exit(0);
        }, 1000);
    })
    .catch((err) => {
        console.error('✗ Error publishing:', err);
        process.exit(1);
    });
