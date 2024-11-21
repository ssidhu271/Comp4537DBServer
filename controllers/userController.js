//ChatGPT helped with the creation of this file

const { db, getQuery, runQuery } = require('../utils/dbHelper');
const { incrementApiUsage } = require('../controllers/apiController');
const parseBody = require('../utils/parseBody')

const getUserData = async (req, res, user) => {
    incrementApiUsage('/api/getUserData', 'GET', user.id);

    try {
        // Calculate total API calls specifically for the /api/llm endpoint for this user
        const totalCallsResult = await getQuery(
            'SELECT SUM(request_count) as total_calls FROM api_usage_logs WHERE user_id = ? AND endpoint = ?',
            [user.id, '/api/LLM']
        );

        const totalCalls = totalCallsResult.total_calls || 0;
        const userExceededLimit = totalCalls >= 20;

        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
            api_calls: totalCalls,
            message: userExceededLimit ? 'API call limit exceeded' : 'API calls within limit',
            status: userExceededLimit ? 'warning' : 'ok'
        }));
    } catch (error) {
        console.error('Error in getUserData:', error);
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Server error' }));
    }
};

const updateUserRole = async (req, res) => {
    // Check if the requesting user is an admin
    if (!req.user || req.user.role !== 'admin') {
        res.statusCode = 403;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Access denied' }));
        return;
    }

    incrementApiUsage('/api/updateUserRole', 'PUT', req.user.id);

    try {
        const { userId, newRole } = await parseBody(req);

        // Retrieve the role_id for the specified new role
        const roleResult = await getQuery(
            `
            SELECT id AS role_id
            FROM roles
            WHERE role_name = ?
            `,
            [newRole]
        );

        if (!roleResult) {
            res.statusCode = 400;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: 'Invalid role specified' }));
            return;
        }

        const roleId = roleResult.role_id;

        // Update the user's role in the database
        await runQuery(
            `
            UPDATE users
            SET role_id = ?
            WHERE id = ?
            `,
            [roleId, userId]
        );

        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ message: 'User role updated successfully' }));
    } catch (error) {
        console.error('Error updating user role:', error);
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Failed to update user role' }));
    }
};



module.exports = { getUserData, updateUserRole };
