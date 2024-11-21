const https = require('https');
const http = require('http'); // Use http module for HTTP URLs
const { parse } = require('url');
const { incrementApiUsage } = require('../controllers/apiController');
const parseBody = require('../utils/parseBody');

function forwardRequestToProjectExpress(instrument) {
    const url = `https://comp4537-project-express-ckfph6esbdfpffg0.canadacentral-01.azurewebsites.net/api/get-model-url?instrument=${encodeURIComponent(instrument)}`;

    return new Promise((resolve, reject) => {
        http.get(url, (res) => {
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

// Function to handle the /api/get-model-url route
async function handleModelUrlRequest(req, res) {
    const { query } = parse(req.url, true);
    const { instrument } = query;

    const userId = req.user.id;
    incrementApiUsage('/api/LLM', 'GET', userId);

    // Validate the query parameter
    if (!instrument || typeof instrument !== 'string' || instrument.trim() === '') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Instrument is required and must be a valid string.' }));
        return;
    }

    try {
        // Forward the request to project-express
        const projectExpressResponse = await forwardRequestToProjectExpress(instrument);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(projectExpressResponse));
    } catch (error) {
        console.error("Error forwarding request to project-express:", error.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: "Failed to fetch model URL from project-express" }));
    }
}

module.exports = { handleModelUrlRequest };
