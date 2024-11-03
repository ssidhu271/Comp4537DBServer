const { allQuery, getQuery, runQuery } = require('../utils/dbHelper'); // Use the helper functions

// Function to retrieve admin data
const getAdminData = async (req, res) => {
    const user = req.user;
    if (user.role !== 'admin') {
        res.statusCode = 403;
        res.setHeader('Content-Type', 'application/json');
        return res.end(JSON.stringify({ error: 'Access denied' }));
    }

    try {
        const allUsers = await allQuery('SELECT email, api_calls FROM users');
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

module.exports = { getAdminData, incrementApiCall };
