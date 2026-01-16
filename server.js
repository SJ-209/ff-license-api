// -----------------------------------------------------
// 2. LICENSE VALIDATION ENDPOINT
// -----------------------------------------------------
app.post('/api/validate-license', async (req, res) => {
    const { license_key, instance_id } = req.body;
    
    // IMPORTANT SECRETS (from Render Environment Variables)
    const PRODUCT_ID = process.env.PRODUCT_ID; 

    if (!license_key || !instance_id) {
        return res.status(400).json({ status: 'error', message: 'Key and Instance ID are required.' });
    }

    try {
        // A. 1st Check: Local Postgres DB (Fast!)
        const dbResult = await pool.query(
            'SELECT status FROM license_activations WHERE license_key = $1 AND extension_instance_id = $2',
            [license_key, instance_id]
        );

        if (dbResult.rows.length > 0) {
            const status = dbResult.rows[0].status;
            if (status === 'active') {
                return res.status(200).json({ status: 'active', valid: true, message: 'Active from local cache.' });
            } else {
                return res.status(403).json({ status: status, valid: false, message: `License ${status}.` });
            }
        }
        
        // B. 2nd Check: Activate with Lemon Squeezy
        console.log("Attempting activation via Lemon Squeezy...");
        
        const payload = new URLSearchParams({
            license_key: license_key, 
            instance_name: instance_id 
        }).toString();

        const ls_response = await axios.post('https://api.lemonsqueezy.com/v1/licenses/activate', payload, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json',
            }
        });

        // --- UNIVERSAL SUCCESS HANDLING START ---
        const responseData = ls_response.data;

        // 1. Get the license object (where status and test_mode live)
        const license_key_data = responseData.license_key || responseData;
        
        // 2. Get the meta object (where product_id lives)
        // We look at the top level first, then inside the license_key object
        const meta = responseData.meta || license_key_data.meta;

        const ls_status = license_key_data.status;
        let ls_product_id;

        // 3. Logic: Extract Product ID or handle Test Mode bypass
        if (meta && meta.product_id) {
            ls_product_id = meta.product_id;
        } 
        else if (license_key_data.test_mode === true && ls_status === 'active') {
            console.warn("Bypassing product ID check for active Test Mode Key.");
            ls_product_id = PRODUCT_ID; 
        }
        else {
            console.error("FAILED: No product_id found in meta.");
            throw new Error("Activation failed or response is missing product ID data.");
        }

        // 4. Comparison Check
        console.log(`DEBUG: Comparing Env ID (${PRODUCT_ID}) against Key ID (${ls_product_id})`);

        if (String(ls_product_id) !== String(PRODUCT_ID)) { 
            console.error(`Product ID Mismatch: Expected ${PRODUCT_ID}, got ${ls_product_id}`);
            return res.status(403).json({ status: 'error', message: 'Invalid product for this key.' });
        }

        if (ls_status === 'active') {
            // C. 3rd Step: Save to Database
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
            res.status(403).json({ status: ls_status, valid: false, message: `License status is ${ls_status}.` });
        }

    } catch (error) {
        // --- ROBUST ERROR HANDLING ---
        let ls_error_message = error.message;
        let http_status = 500; 

        if (error.response) {
            http_status = error.response.status;
            const resData = error.response.data;
            ls_error_message = resData.error || (resData.errors && resData.errors[0].detail) || "Lemon Squeezy API Error";
            console.error('LS API Error:', resData);
        } else {
            console.error('Local Catch Error:', error.message);
        }

        res.status(http_status).json({ 
            status: 'failed', 
            valid: false, 
            message: `License check failed: ${ls_error_message}` 
        });
    }
});