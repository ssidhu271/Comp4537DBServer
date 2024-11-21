const https = require('https');
const { parse } = require('url');
const { incrementApiUsage } = require('../controllers/apiController');

// Forward request to project-express
function forwardRequestToProjectExpress(instrument) {
    const url = `https://comp4537-project-express-ckfph6esbdfpffg0.canadacentral-01.azurewebsites.net/api/get-model-url?instrument=${encodeURIComponent(instrument)}`;

    return new Promise((resolve, reject) => {
        https.get(url, (res) => {
            let data = '';

            // Accumulate data chunks
            res.on('data', (chunk) => {
                data += chunk;
            });

            // Resolve promise when response ends
            res.on('end', () => {
                try {
                    const jsonData = JSON.parse(data);
                    resolve(jsonData);
                } catch (error) {
                    reject(new Error("Failed to parse JSON response from project-express"));
                }
            });
        }).on('error', (err) => {
            reject(err);
        });
    });
}

// Handle /api/get-model-url route
async function handleModelUrlRequest(req, res) {
    const { query } = parse(req.url, true);
    const { instrument } = query;

    // Get origin from headers
    const origin = req.headers.origin;
    const allowedOrigin = 'https://happy-island-03f35251e.5.azurestaticapps.net';

    // Increment API usage
    const userId = req.user?.id; // Safely access user ID
    incrementApiUsage('/api/LLM', 'GET', userId);

    // Validate the instrument parameter
    if (!instrument || typeof instrument !== 'string' || instrument.trim() === '') {
        res.writeHead(400, {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': origin === allowedOrigin,
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        });
        res.end(JSON.stringify({ error: 'Instrument is required and must be a valid string.' }));
        return;
    }

    try {
        // Forward the request to project-express
        const projectExpressResponse = await forwardRequestToProjectExpress(instrument);

        // Add CORS headers and send the response
        res.writeHead(200, {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': origin === allowedOrigin,
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        });
        res.end(JSON.stringify(projectExpressResponse));
    } catch (error) {
        console.error("Error forwarding request to project-express:", error.message);

        // Handle errors with CORS headers
        res.writeHead(500, {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': origin === allowedOrigin,
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        });
        res.end(JSON.stringify({ error: "Failed to fetch model URL from project-express" }));
    }
}

module.exports = { handleModelUrlRequest };
