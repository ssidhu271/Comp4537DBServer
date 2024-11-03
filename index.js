//ChatGPT helped with the creation of this file

const http = require('http');
const { parse } = require('url');
const initializeDatabase = require('./initDB'); 
const { login, register, forgotPassword, resetPassword, validateToken } = require('./controllers/authController');
const { getAdminData, incrementApiCall } = require('./controllers/apiController');
const { getUserData } = require('./controllers/userController');
const handleCors = require('./middlewares/handleCors');
const verifyToken = require('./middlewares/verifyToken');
require('dotenv').config();

const PORT = process.env.PORT || 8888;

initializeDatabase().then(() => {
    const server = http.createServer(async (req, res) => {
        handleCors(req, res);
        if (req.method === 'OPTIONS') return;

        const { pathname } = parse(req.url, true);

        if (pathname === '/auth/validate' && req.method === 'GET') {
            validateToken(req, res);
        } else if (pathname === '/login' && req.method === 'POST') {
            await login(req, res);
        } else if (pathname === '/register' && req.method === 'POST') {
            await register(req, res);
        } else if (pathname === '/forgot-password' && req.method === 'POST') {
            await forgotPassword(req, res);
        } else if (pathname === '/reset-password' && req.method === 'POST') {
            await resetPassword(req, res);
        } else if (pathname === '/api/user-data' && req.method === 'GET') {
            verifyToken(req, res, () => getUserData(req, res, req.user));
        } else if (pathname === '/api/admin-data' && req.method === 'GET') {
            verifyToken(req, res, () => getAdminData(req, res, req.user));
        } else if (pathname === '/api/increment-api-call' && req.method === 'POST') {
            verifyToken(req, res, () => incrementApiCall(req, res, req.user));
        } else {
            res.statusCode = 404;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: 'Route not found' }));
        }
    });

    server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}).catch(error => {
    console.error("Error initializing database:", error);
});
