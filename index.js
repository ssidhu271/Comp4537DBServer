// ChatGPT helped with the creation of this file

const http = require('http');
const fs = require('fs');
const path = require('path');
const { parse } = require('url');
const initializeDatabase = require('./initDB');
const { login, register, forgotPassword, resetPassword, validateToken } = require('./controllers/authController');
const { getAdminData, incrementApiCall, getApiUsageStats} = require('./controllers/apiController');
const { getUserData, updateUserRole } = require('./controllers/userController');
const { addWavFile, getWavFilesByUser, updateWavFileName, deleteWavFile } = require('./controllers/wavController');
const handleCors = require('./middlewares/handleCors');
const verifyToken = require('./middlewares/verifyToken');
require('dotenv').config();

const PORT = process.env.PORT || 8888;

initializeDatabase().then(() => {
    const server = http.createServer(async (req, res) => {
        handleCors(req, res);
        if (req.method === 'OPTIONS') return;

        const { pathname, query } = parse(req.url, true);

        // Serve files from /uploads
        if (pathname.startsWith('/uploads/')) {
            const filePath = path.join(__dirname, pathname);
            if (fs.existsSync(filePath)) {
                res.writeHead(200, {
                    'Content-Type': 'audio/wav',
                    'Content-Disposition': `attachment; filename="${path.basename(filePath)}"`
                });
                fs.createReadStream(filePath).pipe(res);
            } else {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('File not found');
            }
            return;
        }

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
        } else if (pathname === '/wav-files' && req.method === 'POST') {
            verifyToken(req, res, () => addWavFile(req, res));
        } else if (pathname === '/wav-files' && req.method === 'GET') {
            verifyToken(req, res, () => getWavFilesByUser(req, res));
        } else if (pathname.startsWith('/wav-files/') && req.method === 'PUT') {
            const id = pathname.split('/').pop();
            req.params = { id };
            verifyToken(req, res, () => updateWavFileName(req, res));
        } else if (pathname.startsWith('/wav-files/') && req.method === 'DELETE') {
            const id = pathname.split('/').pop();
            req.params = { id };
            verifyToken(req, res, () => deleteWavFile(req, res));
        } else if (pathname === '/api/usage-stats' && req.method === 'GET') {
            verifyToken(req, res, () => getApiUsageStats(req, res));
        } else if (pathname === '/api/update-role' && req.method === 'PUT') {
            verifyToken(req, res, () => updateUserRole(req, res));
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
