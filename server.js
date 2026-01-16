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
    const PRODUCT_ID = process.env.PRODUCT_ID; 

    if (!license_key || !instance_id) {
        return res.status(400).json({ status: 'error', message: 'Key and Instance ID are required.' });
    }

    try {
        // A. Local Cache Check
        const dbResult = await pool.query(
            'SELECT status FROM license_activations WHERE license_key = $1 AND extension_instance_id = $2',
            [license_key, instance_id]
        );

        if (dbResult.rows.length > 0) {
            const status = dbResult.rows[0].status;
            if (status === 'active') return res.status(200).json({ status: 'active', valid: true });
            return res.status(403).json({ status, valid: false, message: `License is ${status}` });
        }
        
        // B. Lemon Squeezy Activation
        const payload = new URLSearchParams({ license_key, instance_name: instance_id }).toString();
        const ls_response = await axios.post('https://api.lemonsqueezy.com/v1/licenses/activate', payload, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' }
        });

        const responseData = ls_response.data;
        const license_key_data = responseData.license_key || responseData;
        const meta = responseData.meta || license_key_data.meta;
        const ls_status = license_key_data.status;

        let ls_product_id;
        if (meta && meta.product_id) {
            ls_product_id = meta.product_id;
        } else if (license_key_data.test_mode === true && ls_status === 'active') {
            ls_product_id = PRODUCT_ID; 
        } else {
            throw new Error("Missing product ID in response.");
        }

        // Verify Product ID matches your Render Env Var
        if (String(ls_product_id) !== String(PRODUCT_ID)) { 
            return res.status(403).json({ status: 'error', message: 'Product ID Mismatch' });
        }

        if (ls_status === 'active') {
            await pool.query(
                'INSERT INTO license_activations (license_key, extension_instance_id, status) VALUES ($1, $2, $3) ON CONFLICT (extension_instance_id) DO UPDATE SET status = $3',
                [license_key, instance_id, 'active']
            );
            return res.status(200).json({ status: 'active', valid: true });
        }

        res.status(403).json({ status: ls_status, valid: false });

    } catch (error) {
        console.error('Validation Error:', error.message);
        res.status(500).json({ status: 'failed', message: error.message });
    }
});

// --- 4. WEBHOOK HANDLER ---
app.post('/api/ls-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const secret = process.env.LS_WEBHOOK_SECRET;
    const hmac = crypto.createHmac('sha256', secret);
    const digest = Buffer.from(hmac.update(req.body).digest('hex'), 'utf8');
    const signature = Buffer.from(req.headers['x-signature'] || '', 'utf8');

    if (!crypto.timingSafeEqual(digest, signature)) return res.status(400).send("Invalid Signature");
    
    try {
        const event = JSON.parse(req.body.toString());
        const eventName = event.meta.event_name;
        const licenseKey = event.data.attributes.license_key; 

        if (eventName === 'order_refunded' || eventName === 'license_disabled') {
            await pool.query('UPDATE license_activations SET status = $1 WHERE license_key = $2', ['refunded', licenseKey]);
            console.log(`License ${licenseKey} revoked.`);
        }
        
        // IMPORTANT: Always return 200 to Lemon Squeezy if signature is valid
        res.status(200).send("Webhook Processed");

    } catch (dbError) {
        console.error("WEBHOOK ERROR:", dbError.message);
        res.status(200).send("Error but received"); 
    }
});

app.listen(PORT, () => console.log(`Server live on port ${PORT}`));