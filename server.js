// server.js
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto'); // Used for Webhook signature verification
const app = express();
const { Pool } = require('pg');
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


// The Internal Database URL will be provided as an Environment Variable
const dbUrl = process.env.DATABASE_URL; 

if (!dbUrl) {
    console.error("FATAL ERROR: DATABASE_URL environment variable is not set!");
    // Exit if the database connection string is missing
    process.exit(1); 
}

const pool = new Pool({
    connectionString: dbUrl,
    // Add SSL support if connecting from outside Render's internal network (good practice)
    ssl: {
        rejectUnauthorized: false 
    }
});

const CREATE_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS license_activations (
        id SERIAL PRIMARY KEY,
        license_key VARCHAR(255) UNIQUE NOT NULL,
        extension_instance_id VARCHAR(255) UNIQUE,
        status VARCHAR(50) DEFAULT 'active' NOT NULL, -- 'active', 'refunded', 'disabled'
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
`;

// Test connection AND Run Schema
pool.connect()
    .then(client => {
        console.log("Postgres connected successfully!");
        
        // --- THIS IS THE CRITICAL STEP ---
        // Run the CREATE TABLE query to ensure the table exists
        return client.query(CREATE_TABLE_SQL)
            .then(() => {
                console.log("Database schema confirmed: license_activations table is ready.");
                client.release();
            })
            .catch(schemaErr => {
                console.error("Error creating schema:", schemaErr.message);
                client.release();
                // Optionally exit the process if the schema is essential
            });
    })
    .catch(err => {
        console.error("FATAL: Postgres connection error:", err.message);
        process.exit(1); 
    });

// -----------------------------------------------------
// 2. LICENSE VALIDATION ENDPOINT (Called by Chrome Extension)
// -----------------------------------------------------

app.post('/api/validate-license', async (req, res) => {
    const { license_key, instance_id } = req.body; // Expecting instance_id from extension
    
    // IMPORTANT SECRETS (from Render Environment Variables)
    const LEMON_SQUEEZY_API_KEY = process.env.LEMON_SQUEEZY_API_KEY;
    const PRODUCT_ID = process.env.PRODUCT_ID; 

    if (!license_key || !instance_id) {
        return res.status(400).json({ status: 'error', message: 'Key and Instance ID are required.' });
    }

    try {
        // A. 1st Check: Look up status in your local Postgres DB (Fast!)
        const dbResult = await pool.query(
            'SELECT status FROM license_activations WHERE license_key = $1 AND extension_instance_id = $2',
            [license_key, instance_id]
        );

        if (dbResult.rows.length > 0) {
            const status = dbResult.rows[0].status;
            if (status === 'active') {
                return res.status(200).json({ status: 'active', valid: true, message: 'Active from local cache.' });
            } else {
                // Key found but marked refunded/disabled in our DB
                return res.status(403).json({ status: status, valid: false, message: `License ${status}.` });
            }
        }

        // B. 2nd Check: If not found in DB, try to ACTIVATE/VALIDATE with Lemon Squeezy
        console.log("License not found locally. Attempting activation via Lemon Squeezy...");

        const ls_response = await axios.post('https://api.lemonsqueezy.com/v1/licenses/activate', {
            license_key: license_key,
            instance_name: instance_id // Use the extension's unique ID for tracking
        }, {
            headers: {
                'Authorization': `Bearer ${LEMON_SQUEEZY_API_KEY}`, 
                'Accept': 'application/json',
            }
        });

        const data = ls_response.data.data.attributes;
        
        if (String(data.product_id) !== String(PRODUCT_ID)) {
             return res.status(403).json({ status: 'error', message: 'Invalid product for this key.' });
        }

        if (data.valid) {
            // Activation was successful or key was already active on this instance.
            
            // C. 3rd Step: Insert the new active license into your DB
            await pool.query(
                'INSERT INTO license_activations (license_key, extension_instance_id, status) VALUES ($1, $2, $3) ON CONFLICT (extension_instance_id) DO NOTHING',
                [license_key, instance_id, 'active']
            );

            res.status(200).json({ 
                status: 'active', 
                valid: true, 
                message: 'Activation successful.'
            });
        } else {
            res.status(403).json({ status: 'inactive', valid: false, message: 'License invalid or activation limit reached.' });
        }

    } catch (error) {
        // LS API error, including activation limit reached (which returns 4xx status)
        const errorMessage = error.response?.data?.error || error.message;
        console.error('Validation Error:', errorMessage);
        res.status(500).json({ status: 'error', message: `Server error or activation failed: ${errorMessage}` });
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