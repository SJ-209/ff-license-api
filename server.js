// server.js
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto'); // Used for Webhook signature verification
const app = express();
const PORT = process.env.PORT || 10000;

// -----------------------------------------------------
// 1. MIDDLEWARE SETUP
// -----------------------------------------------------

// CORS: REQUIRED to allow your Chrome Extension to call this API
// In production, tighten this by replacing '*' with your specific extension ID
app.use(cors());

// Body Parsers: 
// a) express.json() for standard API calls (License Validation)
// b) express.raw() is needed specifically for the Webhook route to get the raw body
app.use(express.json());


// -----------------------------------------------------
// 2. LICENSE VALIDATION ENDPOINT (Called by Chrome Extension)
// -----------------------------------------------------

app.post('/api/validate-license', async (req, res) => {
    const { license_key } = req.body;
    
    // IMPORTANT SECRETS (from Render Environment Variables)
    const LEMON_SQUEEZY_API_KEY = process.env.LEMON_SQUEEZY_API_KEY;
    const PRODUCT_ID = process.env.PRODUCT_ID; 

    if (!license_key) {
        return res.status(400).json({ status: 'error', message: 'License key is required.' });
    }

    try {
        // Securely call the Lemon Squeezy License API (Server-to-Server)
        const ls_response = await axios.post('https://api.lemonsqueezy.com/v1/licenses/validate', {
            license_key: license_key
        }, {
            headers: {
                'Authorization': `Bearer ${LEMON_SQUEEZY_API_KEY}`, 
                'Accept': 'application/json',
            }
        });

        const data = ls_response.data.data.attributes; 
        
        // 🚨 Critical Security Check: Ensure the key is for YOUR product
        if (String(data.product_id) !== String(PRODUCT_ID)) {
             return res.status(403).json({ status: 'error', message: 'Invalid product for this key.' });
        }

        // Check if the license is valid (active or grace period)
        if (data.valid) {
            // In a real app, you would also check activation limits and log the extension instance ID here.
            res.status(200).json({ 
                status: 'active', 
                valid: true, 
                expires: data.expires_at 
            });
        } else {
            res.status(403).json({ status: 'inactive', valid: false, message: 'License expired or disabled.' });
        }

    } catch (error) {
        // Handle network errors or LS API returning a non-200 status
        console.error('Validation Error:', error.response?.data || error.message);
        res.status(500).json({ status: 'error', message: 'Could not validate license.' });
    }
});


// -----------------------------------------------------
// 3. WEBHOOK HANDLER (Called by Lemon Squeezy on cancellation)
// -----------------------------------------------------

app.post('/api/ls-webhook', express.raw({ type: 'application/json' }), (req, res) => {
    // IMPORTANT: Webhooks must be verified to prevent malicious users from faking a cancellation!
    const secret = process.env.LS_WEBHOOK_SECRET;
    const hmac = crypto.createHmac('sha256', secret);
    const digest = Buffer.from(hmac.update(req.body).digest('hex'), 'utf8');
    const signature = Buffer.from(req.headers['x-signature'] || '', 'utf8');

    let sigOK = false;
    try {
        sigOK = crypto.timingSafeEqual(digest, signature);
    } catch (err) {
        console.error("ERROR: timingSafeEqual:", err);
    }

    if (!sigOK) {
        console.log("ERROR: Invalid signature received for webhook.");
        return res.status(400).send("ERROR: Invalid signature");
    }
    
    // Parse the verified raw body
    const event = JSON.parse(req.body.toString());
    const eventName = event.meta.event_name;
    const licenseId = event.data.attributes.license_id;

    console.log(`Verified Webhook Event Received: ${eventName} for License ID: ${licenseId}`);

    // --- YOUR REVOCATION LOGIC GOES HERE ---
    if (eventName === 'subscription_cancelled' || eventName === 'subscription_expired') {
        // **This is where you would call your database (e.g., Firebase, Render Postgres) 
        // to set the status of licenseId to 'revoked'**
        console.log(`ACTION: Revoking premium status for License ID ${licenseId}`);
    }

    // Must return 200 OK quickly to acknowledge receipt and prevent retries
    res.sendStatus(200); 
});


// -----------------------------------------------------
// 4. START SERVER
// -----------------------------------------------------
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});