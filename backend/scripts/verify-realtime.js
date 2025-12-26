const axios = require('axios');
const EventSource = require('eventsource');
const { spawn } = require('child_process');

// Configuration
const BASE_URL = 'http://localhost:10000';
const ADMIN_EMAIL = 'admin@ctf.com'; // Adjust if needed
const ADMIN_PASSWORD = 'admin'; // Adjust if needed
// You might need to Create an admin or use existing one.
// We can use the create-admin script or just assume one exists if we know credentials.
// Let's assume standard test admin credentials or fetching from .env if possible? 
// For now I'll hardcode common ones or try to create one.

async function runVerification() {
    try {
        console.log('1. Logging in as Admin...');
        const loginRes = await axios.post(`${BASE_URL}/api/auth/login`, {
            email: 'test@admin.com',
            password: '123456'
        });

        if (!loginRes.data.token) throw new Error('Login failed, no token');
        const token = loginRes.data.token;
        console.log('   Login successful. Token acquired.');

        console.log('2. Connecting to SSE Endpoint...');
        const sseUrl = `${BASE_URL}/r-submission?token=${token}`;
        const es = new EventSource(sseUrl);

        let messageReceived = false;

        es.onopen = () => {
            console.log('   SSE Connected!');
        };

        es.onmessage = (event) => {
            console.log('   SSE Message Received:', event.data);
            const data = JSON.parse(event.data);
            if (data.type !== 'connected') {
                messageReceived = true;
                console.log('   ✅ Verification SUCCESS: Received submission event!');
                es.close();
                process.exit(0);
            }
        };

        es.onerror = (err) => {
            // console.error('   SSE Error:', err);
        };

        // 3. Simulate a Submission (Mocking via Redis directly or calling endpoint?)
        // Calling the endpoint requires a user and a challenge.
        // To avoid complex setup, I will manually PUBLISH to redis using a script or use the /test route if we had one.
        // Or I can rely on `checkConnection.js` style approach but that's just checking DB.

        // Let's trigger a manual publish via a helper script we create on the fly, 
        // OR we can try to submit a flag if we have a valid user and challenge.
        // Simpler: Just publish to Redis using ioredis in this script to mock the backend behavior.

        setTimeout(async () => {
            console.log('3. Simulating Submission Event via Redis...');
            const Redis = require('ioredis');
            const redis = new Redis('redis://localhost:6379');

            await redis.publish('ctf:submissions:live', JSON.stringify({
                user: 'TestUser',
                flag: 'CTF{test}',
                ip: '127.0.0.1',
                submittedAt: new Date().toISOString(),
                points: 100,
                challenge: 'Sanity Check'
            }));

            console.log('   Event published to Redis.');
            redis.disconnect();
        }, 2000);

        // Timeout
        setTimeout(() => {
            if (!messageReceived) {
                console.error('   ❌ Verification FAILED: Timeout waiting for event.');
                process.exit(1);
            }
        }, 5000);

    } catch (err) {
        if (err.response) {
            console.error('Login Failed Status:', err.response.status);
            console.error('Data:', err.response.data);
        } else {
            console.error('Error:', err.message);
        }
        process.exit(1);
    }
}

runVerification();
