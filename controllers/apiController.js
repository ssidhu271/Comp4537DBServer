//ChatGPT helped with the creation of this file

const { allQuery, getQuery, runQuery } = require('../utils/dbHelper'); // Use the helper functions

// Function to retrieve admin data
const getAdminData = async (req, res) => {
    incrementApiUsage('/api/admin-data', 'GET');

    const user = req.user;
    if (user.role !== 'admin') {
        res.statusCode = 403;
        res.setHeader('Content-Type', 'application/json');
        return res.end(JSON.stringify({ error: 'Access denied' }));
    }

    try {
        const allUsers = await allQuery('SELECT email, api_calls, id, role FROM users');
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ data: allUsers }));
    } catch (err) {
        console.error('Error retrieving admin data:', err);
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Failed to retrieve users data' }));
    }
};

// Function to increment API call count
const incrementApiCall = async (req, res) => {
    const user = req.user;

    try {
        const row = await getQuery('SELECT * FROM users WHERE id = ?', [user.id]);

        if (!row) {
            res.statusCode = 500;
            res.setHeader('Content-Type', 'application/json');
            return res.end(JSON.stringify({ error: 'Failed to retrieve user data' }));
        }

        // Only proceed to increment if the user has not exceeded 20 calls or is an admin
        if (row.api_calls < 20 || row.role === 'admin') {
            await runQuery('UPDATE users SET api_calls = api_calls + 1 WHERE id = ?', [user.id]);
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ message: 'API call incremented successfully' }));
        } else {
            res.statusCode = 403;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ warning: 'API call limit exceeded' }));
        }
    } catch (err) {
        console.error('Error incrementing API call count:', err);
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Failed to increment API calls' }));
    }
};

const incrementApiUsage = async (endpoint, method) => {
    try {
        // Check if the endpoint-method combination already exists
        const existingLog = await getQuery(
            'SELECT * FROM api_usage_logs WHERE endpoint = ? AND method = ?',
            [endpoint, method]
        );

        if (existingLog) {
            // If the record exists, update the request count
            await runQuery(
                'UPDATE api_usage_logs SET request_count = request_count + 1 WHERE endpoint = ? AND method = ?',
                [endpoint, method]
            );
        } else {
            // If the record doesn't exist, insert a new one
            await runQuery(
                'INSERT INTO api_usage_logs (endpoint, method, request_count) VALUES (?, ?, 1)',
                [endpoint, method]
            );
        }
    } catch (error) {
        console.error("Error incrementing API usage:", error);
    }
};

const getApiUsageStats = async (req, res) => {
    const user = req.user;
    if (user.role !== 'admin') {
        res.statusCode = 403;
        res.setHeader('Content-Type', 'application/json');
        return res.end(JSON.stringify({ error: 'Access denied' }));
    }

    try {
        const stats = await allQuery(`
            SELECT endpoint, method, request_count
            FROM api_usage_logs
            ORDER BY endpoint, method
        `);

        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ data: stats }));
    } catch (error) {
        console.error("Error retrieving API usage stats:", error.message);
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Failed to retrieve API usage stats' }));
    }
};

module.exports = { getAdminData, incrementApiCall, incrementApiUsage, getApiUsageStats };
