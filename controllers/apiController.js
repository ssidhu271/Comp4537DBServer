//ChatGPT helped with the creation of this file

const { allQuery, getQuery, runQuery } = require('../utils/dbHelper'); // Use the helper functions

// Function to retrieve admin data
const getAdminData = async (req, res) => {
    const user = req.user;

    // Track API usage only if the user is authenticated
    if (user && user.id) {
        incrementApiUsage('/api/admin-data', 'GET', user.id);
    }

    try {
        // Check if the user has admin privileges by fetching the role dynamically
        const userRoleResult = await getQuery(
            `
            SELECT r.role_name
            FROM users u
            INNER JOIN roles r ON u.role_id = r.id
            WHERE u.id = ?
            `,
            [user.id]
        );

        const userRole = userRoleResult?.role_name;
        if (userRole !== 'admin') {
            res.statusCode = 403;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: 'Access denied' }));
            return;
        }

        // Retrieve all users with their roles
        const allUsers = await allQuery(
            `
            SELECT u.id, u.email, r.role_name AS role
            FROM users u
            INNER JOIN roles r ON u.role_id = r.id
            `
        );

        // Map each user to include total and /api/llm-specific API call counts
        const usersWithApiCounts = await Promise.all(
            allUsers.map(async (user) => {
                const totalCallsResult = await getQuery(
                    'SELECT SUM(request_count) as total_calls FROM api_usage_logs WHERE user_id = ?',
                    [user.id]
                );

                const llmCallsResult = await getQuery(
                    'SELECT SUM(request_count) as llm_calls FROM api_usage_logs WHERE user_id = ? AND endpoint = ?',
                    [user.id, '/api/LLM']
                );

                return {
                    ...user,
                    total_calls: totalCallsResult.total_calls || 0,
                    llm_calls: llmCallsResult.llm_calls || 0,
                };
            })
        );

        // Set status code and headers for successful response
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ data: usersWithApiCounts }));
    } catch (err) {
        console.error('Error retrieving admin data:', err);

        // Set status code and headers for error response
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Failed to retrieve users data' }));
    }
};

// Function to increment API call count
const incrementApiCall = async (req, res) => {
    const user = req.user;

    try {
        // Check total /api/llm call count for this user
        const totalCalls = await getQuery(
            'SELECT SUM(request_count) as total FROM api_usage_logs WHERE user_id = ?', 
            [user.id]
        );

        // Allow increment if within limit or if user is admin
        if (!totalCalls || (totalCalls.total < 20 || user.role === 'admin')) {
            await runQuery(
                `INSERT INTO api_usage_logs (user_id, endpoint, method, request_count)
                VALUES (?, '/api/llm', 'POST', 1)
                ON CONFLICT(user_id, endpoint, method)
                DO UPDATE SET request_count = request_count + 1`,
                [user.id]
            );
            
            // Set status code and headers for successful increment
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ message: 'API call incremented successfully' }));
        } else {
            // Set status code and headers for exceeded limit
            res.statusCode = 403;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ warning: 'API call limit exceeded' }));
        }
    } catch (err) {
        console.error('Error incrementing API call count:', err);
        
        // Set status code and headers for error
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Failed to increment API calls' }));
    }
};


const incrementApiUsage = async (endpoint, method, userId) => {
    if (!userId) {
        console.error("Error: Missing user ID for API usage logging");
        return;
    }

    try {
        const existingLog = await getQuery(
            'SELECT * FROM api_usage_logs WHERE endpoint = ? AND method = ? AND user_id = ?',
            [endpoint, method, userId]
        );

        if (existingLog) {
            await runQuery(
                'UPDATE api_usage_logs SET request_count = request_count + 1 WHERE endpoint = ? AND method = ? AND user_id = ?',
                [endpoint, method, userId]
            );
        } else {
            await runQuery(
                'INSERT INTO api_usage_logs (endpoint, method, request_count, user_id) VALUES (?, ?, 1, ?)',
                [endpoint, method, userId]
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
            GROUP BY endpoint, method
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
