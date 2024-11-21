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
const { handleModelUrlRequest } = require('./middlewares/llmServer');
require('dotenv').config();

const PORT = process.env.PORT || 8888;
const swaggerUiPath = path.join(__dirname, "swagger-ui-dist");

function serveSwaggerJSON(req, res) {
    const filePath = path.join(__dirname, "swagger.json");
    fs.readFile(filePath, "utf8", (err, data) => {
      if (err) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Swagger JSON not found" }));
      } else {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(data);
      }
    });
  }
  
  function serveSwaggerUI(req, res) {
    let filePath;

    // Serve the main HTML file for Swagger UI
    if (req.url === "/doc" || req.url === "/doc/") {
        filePath = path.join(swaggerUiPath, "index.html");
    } else {
        // Serve asset files like CSS and JS by removing "/doc" prefix
        const assetPath = req.url.replace("/doc", ""); // Removes "/doc" from the URL
        filePath = path.join(swaggerUiPath, assetPath); // Map the remaining path to swagger-ui-dist
    }

    fs.readFile(filePath, (err, data) => {
        if (err) {
            console.error(`Error serving file: ${filePath}`, err);
            res.writeHead(404, { "Content-Type": "text/html" });
            res.end("404 Not Found");
            return;
        }

        // Set the appropriate content type based on file extension
        const ext = path.extname(filePath);
        const contentType =
            {
                ".html": "text/html",
                ".css": "text/css",
                ".js": "application/javascript",
                ".png": "image/png",
                ".svg": "image/svg+xml",
                ".json": "application/json",
                ".ico": "image/x-icon",
            }[ext] || "text/plain";

        res.writeHead(200, { "Content-Type": contentType });
        res.end(data);
    });
}

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

        if (pathname === "/swagger.json") {
            serveSwaggerJSON(req, res);
            return;
          }
        
        if (pathname.startsWith("/doc")) {
            serveSwaggerUI(req, res);
            return;
        }

        if (pathname === '/api/v1/auth/validate' && req.method === 'GET') {
            validateToken(req, res);
        } else if (pathname === '/api/v1/login' && req.method === 'POST') {
            await login(req, res);
        } else if (pathname === '/api/v1/register' && req.method === 'POST') {
            await register(req, res);
        } else if (pathname === '/api/v1/forgot-password' && req.method === 'POST') {
            await forgotPassword(req, res);
        } else if (pathname === '/api/v1/reset-password' && req.method === 'POST') {
            await resetPassword(req, res);
        } else if (pathname === '/api/v1/user-data' && req.method === 'GET') {
            verifyToken(req, res, () => getUserData(req, res, req.user));
        } else if (pathname === '/api/v1/admin-data' && req.method === 'GET') {
            verifyToken(req, res, () => getAdminData(req, res, req.user));
        } else if (pathname === '/api/v1/wav-files' && req.method === 'POST') {
            verifyToken(req, res, () => addWavFile(req, res));
        } else if (pathname === '/api/v1/wav-files' && req.method === 'GET') {
            verifyToken(req, res, () => getWavFilesByUser(req, res));
        } else if (pathname.startsWith('/api/v1/wav-files/') && req.method === 'PUT') {
            const id = pathname.split('/').pop();
            req.params = { id };
            verifyToken(req, res, () => updateWavFileName(req, res));
        } else if (pathname.startsWith('/api/v1/wav-files/') && req.method === 'DELETE') {
            const id = pathname.split('/').pop();
            req.params = { id };
            verifyToken(req, res, () => deleteWavFile(req, res));
        } else if (pathname === '/api/v1/usage-stats' && req.method === 'GET') {
            verifyToken(req, res, () => getApiUsageStats(req, res));
        } else if (pathname === '/api/v1/update-role' && req.method === 'PUT') {
            verifyToken(req, res, () => updateUserRole(req, res));
        } else if (pathname === '/api/v1/get-model-url' && req.method === 'GET') {
            verifyToken(req, res, () => handleModelUrlRequest(req, res));
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
