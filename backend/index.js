const express = require('express');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const { generateKeyPair, decryptWithPrivateKey, decryptWithAES, encryptWithAES } = require('./utils');
const cors = require('cors');
const dotenv = require('dotenv');
dotenv.config()

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
    allowedHeaders: ['Content-Type', "Access-Control-Allow-Origin", "x-data-encrypted"],
    exposedHeaders: ["x-data-encrypted"]
}));

// Test route
app.get('/', (req, res) => {
    res.json({ message: "Connection successful" });
});


const keyStorage = {}; // Store session keys

const logTemp = () => {
    const temp = {}
    for (const key in keyStorage) temp[key] =
    {
        ...keyStorage[key],
        publicKey: keyStorage[key].publicKey.slice(0, 10) + '...',
        privateKey: keyStorage[key].privateKey.slice(0, 10) + '...'
    };
    console.log('keyStorage: ', temp);
}

// Get server's public key
app.get('/get_public_key', (req, res) => {
    const keys = generateKeyPair();
    const sessionId = crypto.randomBytes(16).toString('hex');

    keyStorage[sessionId] = {
        publicKey: keys.publicKey,
        privateKey: keys.privateKey,
        timestamp: Date.now()
    };

    console.log("client requested for public key : " + keys.publicKey.slice(0, 10) + '...');
    console.log("also a session id is stored in its cookies for identification : " + sessionId.slice(0, 10) + '...');

    logTemp()

    const oldSessionId = req.cookies.sessionId;

    if (keyStorage[oldSessionId]) {
        return res.json({ message: "sessionId already exists", publicKey: keyStorage[oldSessionId].publicKey })
    }

    res.cookie('sessionId', sessionId, { httpOnly: true, secure: true, sameSite: 'Strict' });
    res.cookie('isSessionSet', true, { secure: true, sameSite: 'Strict' });
    res.json({ publicKey: keys.publicKey });

    // Cleanup expired session keys
    setTimeout(() => {
        if (keyStorage[sessionId])
            delete keyStorage[sessionId]
    }, 5 * 60 * 1000); // 5 min expiration
});

// Set AES session key
app.post('/set_session', (req, res) => {
    const { encryptedAESKey } = req.body;
    const sessionId = req.cookies.sessionId;
    // console.log(sessionId, keyStorage[sessionId]);

    if (!sessionId || !keyStorage[sessionId]) {
        return res.status(401).json({ error: 'Invalid session ID' });
    }

    const keyData = keyStorage[sessionId];
    const aesKey = decryptWithPrivateKey(keyData.privateKey, encryptedAESKey);
    keyStorage[sessionId].secretKey = aesKey;
  
    logTemp();

    res.json({ success: true });
});

// Middleware to decrypt incoming requests
app.use((req, res, next) => {
    if (req.method !== 'POST' || !req.headers["x-data-encrypted"] || !req.body.encryptedData) return next();

    const { iv, encryptedData } = req.body;

    const sessionId = req.cookies.sessionId;

    if (!sessionId || !iv || !encryptedData) {
        return res.status(400).json({ error: 'Invalid request format' });
    }

    const keyData = keyStorage[sessionId];
    if (!keyData || !keyData.secretKey) {
        return res.status(401).json({ error: 'Invalid session ID or missing AES key' });
    }

    req.body = decryptWithAES(keyData.secretKey, iv, encryptedData);

    next();
});

// Middleware to encrypt outgoing responses
app.use((req, res, next) => {
    const originalSend = res.send;

    res.send = function (body) {
        const sessionId = req.cookies.sessionId;
        const keyData = keyStorage[sessionId];

        if (typeof body === 'string' && keyData && keyData.secretKey) {
            const { iv, encryptedData } = encryptWithAES(keyData.secretKey, body);

            // Indicate that the response is encrypted
            res.setHeader('x-data-encrypted', 'true');

            return originalSend.call(this, JSON.stringify({ iv, encryptedData }));
        }

        // If no encryption is applied, send the response as is
        res.setHeader('x-data-encrypted', 'false');
        return originalSend.call(this, body);
    };

    next();
});


// Test route
app.post('/test', (req, res) => {
    console.log(req.body);
    res.json({ data: "Some secure data been sent by mistake" });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
