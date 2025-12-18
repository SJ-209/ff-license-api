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

// server.js - REPLACE THE EXISTING LOGIC INSIDE:
// app.post('/api/validate-license', async (req, res) => { ... });

app.post('/api/validate-license', async (req, res) => {
    const { license_key, instance_id } = req.body;
    console.log("DEBUG: Key received from extension:", license_key);
    
    // IMPORTANT SECRETS (from Render Environment Variables)
    const LEMON_SQUEEZY_API_KEY = process.env.LEMON_SQUEEZY_API_KEY;
    const YOUR_PRODUCT_ID = process.env.YOUR_PRODUCT_ID; 

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
        
        // 1. Prepare the URL-encoded data payload
        const payload = new URLSearchParams({
            // Make absolutely sure you are using the variable from req.body
            license_key: license_key, 
            instance_name: instance_id 
        }).toString();

        // This line is where the magic happens and must be correct:
        const ls_response = await axios.post('https://api.lemonsqueezy.com/v1/licenses/activate', payload, {
            headers: {
                'Authorization': `Bearer ${LEMON_SQUEEZY_API_KEY}`,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json',
            }
        });

        // --- START OF MODIFIED SUCCESS HANDLING ---
        // If we reach here, axios returned a 200 OK status.
        const data = ls_response.data.data.attributes; // Access the attributes object safely

        if (String(data.product_id) !== String(YOUR_PRODUCT_ID)) {
             return res.status(403).json({ status: 'error', message: 'Invalid product for this key.' });
        }

        if (data.valid) {
            // Activation was successful.
            
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
            // This is unlikely if status is 200, but handles explicit 'invalid' flag
            res.status(403).json({ status: 'inactive', valid: false, message: 'License marked as invalid by Lemon Squeezy.' });
        }

    } catch (error) {
        // Axios throws an error if status code is not 2xx.
        // The error object contains the non-2xx response details.
        
        let ls_error_message = 'Activation failed due to an unknown issue.';
        let http_status = 403; // Default to Forbidden

        if (error.response) {
            // This means we received a response from Lemon Squeezy, but it was an error status (e.g., 403, 422).
            const responseData = error.response.data;
            http_status = error.response.status;

            console.error('Lemon Squeezy Error Response Status:', http_status);
            console.error('Lemon Squeezy Error Response Data:', responseData);

            if (responseData.error) {
                 // For some LS errors (e.g., 400), the message is in the top-level 'error' field
                 ls_error_message = responseData.error;
            } else if (responseData.errors && responseData.errors.length > 0) {
                 // For JSON:API errors (e.g., 422 Unprocessable Entity), it's in the 'errors' array
                 ls_error_message = responseData.errors[0].detail;
            } else {
                 ls_error_message = `Server returned status ${http_status}. Check Lemon Squeezy API Key or license validity.`;
            }
        } else {
            // Network error (e.g., connection refusal, DNS failure)
            ls_error_message = `Network or connection failure: ${error.message}`;
            http_status = 500;
        }

        // Return a clean response to the Chrome Extension
        res.status(http_status).json({ 
            status: 'failed', 
            valid: false, 
            message: `License check failed: ${ls_error_message}` 
        });
    }
});


// -----------------------------------------------------
// 3. WEBHOOK HANDLER (Called by Lemon Squeezy on cancellation)
// -----------------------------------------------------

app.post('/api/ls-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
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
    
    try {
        const event = JSON.parse(req.body.toString());
        const eventName = event.meta.event_name;
        
        // The license key is inside the 'attributes' of the 'data' object for most events
        const licenseKey = event.data.attributes.license_key; 

        console.log(`Verified Webhook Event: ${eventName} for Key: ${licenseKey}`);

        // --- REFUND REVOCATION LOGIC ---
        if (eventName === 'order_refunded' || eventName === 'license_disabled') {
            
            // Update the status of ALL instances using this key to 'refunded'
            const updateResult = await pool.query(
                'UPDATE license_activations SET status = $1 WHERE license_key = $2',
                ['refunded', licenseKey]
            );

            console.log(`ACTION: Revoked ${updateResult.rowCount} license activation(s) due to refund.`);
        }
        
        res.status(403).json({ 
            status: 'failed', 
            valid: false, 
            message: `Server error or activation failed: ${ls_error_message}` 
        });

    } catch (dbError) {
        console.error("WEBHOOK DB ERROR:", dbError);
        // Even on internal DB error, we must return 200 OK to Lemon Squeezy to prevent retries
        res.sendStatus(200); 
    }
});


// -----------------------------------------------------
// 4. START SERVER
// -----------------------------------------------------
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});