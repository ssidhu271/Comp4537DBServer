//ChatGPT helped with the creation of this file

const { db, getQuery } = require('../utils/dbHelper');

const getUserData = async (req, res, user) => {
    try {
        const row = await getQuery('SELECT * FROM users WHERE id = ?', [user.id]);

        if (!row) {
            res.statusCode = 500;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: 'Failed to retrieve user data' }));
        } else {
            const userExceededLimit = row.api_calls >= 20;
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({
                api_calls: row.api_calls,
                message: userExceededLimit ? 'API call limit exceeded' : 'API calls within limit',
                status: userExceededLimit ? 'warning' : 'ok'
            }));
        }
    } catch (error) {
        console.error('Error in getUserData:', error);
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Server error' }));
    }
};

module.exports = { getUserData };
