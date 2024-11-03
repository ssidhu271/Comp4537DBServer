//ChatGPT helped with the creation of this file

const jwt = require('jsonwebtoken');
const cookie = require('cookie');

const verifyToken = (req, res, next) => {
    const cookies = cookie.parse(req.headers.cookie || '');
    const token = cookies.jwt;

    if (!token) {
        res.statusCode = 401;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'No token provided' }));
        return;
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            res.statusCode = 403;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: 'Invalid token' }));
            return;
        }
        
        // Attach user data to request for later use
        req.user = decoded;
        
        // Proceed to the next handler
        next();
    });
};

module.exports = verifyToken;
