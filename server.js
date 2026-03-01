// server.js
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 10000;

// --- 1. MIDDLEWARE ---
app.use(cors());

// Webhook MUST be registered before express.json() so it receives raw body for HMAC verification
// Match both /api/ls-webhook and /api/ls-webhook/ to avoid 404 from trailing-slash mismatches
const webhookHandler = express.raw({ type: 'application/json' });
app.post(['/api/ls-webhook', '/api/ls-webhook/'], webhookHandler, async (req, res) => {
    const secret = process.env.LS_WEBHOOK_SECRET;
    if (!secret) {
        console.error('[WEBHOOK] LS_WEBHOOK_SECRET not set');
        return res.status(500).send("Webhook not configured");
    }
    const signature = (req.headers['x-signature'] || '').trim();
    if (!signature) return res.status(400).send("Missing X-Signature");

    const hmac = crypto.createHmac('sha256', secret);
    const digest = Buffer.from(hmac.update(req.body).digest('hex'), 'utf8');
    const sigBuffer = Buffer.from(signature, 'utf8');

    if (digest.length !== sigBuffer.length || !crypto.timingSafeEqual(digest, sigBuffer)) {
        return res.status(400).send("Invalid Signature");
    }

    try {
        const event = JSON.parse(req.body.toString());
        const eventName = event.meta?.event_name;

        console.log(`[WEBHOOK] Received: ${eventName}`);

        let licenseKey = null;
        let shouldRevoke = false;
        const attributes = event.data?.attributes || {};

        // 1. Handle manual status changes (activate, disable, expire)
        if (eventName === 'license_key_updated') {
            licenseKey = attributes.key;
            const status = attributes.status;

            console.log(`[WEBHOOK] license_key_updated for ${licenseKey}: ${status}`);

            if (status === 'disabled' || status === 'expired') {
                shouldRevoke = true;
                console.log(`[WEBHOOK] will revoke key ${licenseKey} due to ${status}`);
            } else if (status === 'active') {
                console.log(`[WEBHOOK] ensuring key ${licenseKey} is marked active in DB`);
                try {
                    await pool.query(
                        'UPDATE license_activations SET status = $1 WHERE license_key = $2',
                        ['active', licenseKey]
                    );
                } catch (dbErr) {
                    console.error('[WEBHOOK] DB update failed for activation:', dbErr.message);
                }
            }
        }

        // 2. Handle Refunds
        if (eventName === 'order_refunded') {
            console.log(`[WEBHOOK] Order ${event.data?.id} was refunded.`);
        }

        // 3. Update Database if revocation is needed
        if (shouldRevoke && licenseKey) {
            const updateResult = await pool.query(
                'UPDATE license_activations SET status = $1 WHERE license_key = $2',
                ['disabled', licenseKey]
            );
            console.log(`ACTION: Revoked ${updateResult.rowCount} activation(s) for key: ${licenseKey}`);
        }

        res.status(200).send("Webhook Processed");
    } catch (err) {
        console.error("[WEBHOOK ERROR]:", err.message);
        res.status(200).send("Error logged");
    }
});

app.use(express.json());

// --- 2. DATABASE SETUP ---
const dbUrl = process.env.DATABASE_URL; 
if (!dbUrl) {
    console.error("FATAL ERROR: DATABASE_URL environment variable is not set!");
    process.exit(1); 
}

const pool = new Pool({
    connectionString: dbUrl,
    ssl: { rejectUnauthorized: false }
});

const CREATE_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS license_activations (
        id SERIAL PRIMARY KEY,
        license_key VARCHAR(255) NOT NULL,
        extension_instance_id VARCHAR(255) UNIQUE,
        status VARCHAR(50) DEFAULT 'active' NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
`;

pool.connect()
    .then(client => {
        console.log("Postgres connected successfully!");
        return client.query(CREATE_TABLE_SQL).then(() => client.release());
    })
    .catch(err => {
        console.error("FATAL: Postgres connection error:", err.message);
        process.exit(1); 
    });

// --- 3. LICENSE VALIDATION ENDPOINT ---
app.post('/api/validate-license', async (req, res) => {
    const { license_key, instance_id } = req.body;
    const PRODUCT_ID = process.env.PRODUCT_ID; // Your live Product ID (e.g., 647685)

    if (!license_key || !instance_id) {
        return res.status(400).json({ status: 'error', message: 'Key and Instance ID are required.' });
    }

    try {
        // 1. FAST CHECK: Look in your local Postgres DB first
        const dbResult = await pool.query(
            'SELECT status FROM license_activations WHERE license_key = $1 AND extension_instance_id = $2',
            [license_key, instance_id]
        );

        if (dbResult.rows.length > 0) {
            const status = dbResult.rows[0].status;
            if (status === 'active') {
                return res.status(200).json({ status: 'active', valid: true });
            } else {
                return res.status(403).json({ status: status, valid: false, message: `License ${status}.` });
            }
        }
        
        // 2. REMOTE CHECK: Call Lemon Squeezy to Activate
        // const payload = new URLSearchParams({
        //     license_key: license_key, 
        //     instance_name: instance_id 
        // }).toString();

        const payload = new URLSearchParams({
            license_key: license_key.trim(), 
            instance_name: instance_id.trim() 
        }).toString();

        const ls_response = await axios.post('https://api.lemonsqueezy.com/v1/licenses/activate', payload, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json',
            }
        });

        const responseData = ls_response.data;

        // --- UNIVERSAL DATA EXTRACTION ---
        // This handles differences between Test Mode and Live keys
        const license_key_data = responseData.license_key || responseData;
        const meta = responseData.meta || license_key_data.meta;
        const ls_status = license_key_data.status;

        let ls_product_id;

        if (meta && meta.product_id) {
            ls_product_id = meta.product_id;
        } else if (license_key_data.test_mode === true) {
            // Test mode keys often don't include a product_id; just use the value
            // configured in your environment and skip the strict comparison below.
            console.warn('[LICENSE] test_mode detected, skipping product_id check');
            ls_product_id = PRODUCT_ID;
        } else {
            throw new Error("Activation failed: Missing product ID data.");
        }

        // 3. VALIDATION: Does the product ID match your extension?
        // Only enforce the check for non-test licenses so that you can freely
        // spin up test keys without needing to track the internal id.
        if (!license_key_data.test_mode && String(ls_product_id) !== String(PRODUCT_ID)) {
            console.error('[LICENSE] product mismatch', { ls_product_id, expected: PRODUCT_ID });
            return res.status(403).json({
                status: 'error',
                message: 'Invalid product for this key.',
                details: { ls_product_id, expected_product_id: PRODUCT_ID }
            });
        }

        // 4. FINALIZATION: If active, save to your DB and unlock the extension
        if (ls_status === 'active') {
            await pool.query(
                'INSERT INTO license_activations (license_key, extension_instance_id, status) VALUES ($1, $2, $3) ON CONFLICT (extension_instance_id) DO UPDATE SET status = $3',
                [license_key, instance_id, 'active']
            );

            return res.status(200).json({ status: 'active', valid: true });
        } else {
            return res.status(403).json({ status: ls_status, valid: false });
        }

    } catch (error) {
        console.error('Validation Error:', error.message);
        res.status(500).json({ status: 'failed', message: error.message });
    }
});

// Health check (helps verify server is reachable when debugging webhook 404s)
app.get('/api/health', (req, res) => res.status(200).json({ ok: true }));

app.listen(PORT, () => {
    console.log(`Server live on port ${PORT}`);
    console.log('Webhook URL: POST /api/ls-webhook');
});