// index.js
const http = require('http');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookie = require('cookie');
const initializeDatabase = require('./initDB'); // Import the DB initialization module
const PORT = process.env.PORT || 3000;
require('dotenv').config();

// Connect to the MySQL database
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: 'myApp'
});

// Helper to create JWT tokens
const createToken = (user) => jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

// Helper to parse JSON requests
const parseBody = (req) => new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => resolve(JSON.parse(body)));
    req.on('error', reject);
});

// Middleware to handle CORS and OPTIONS requests
const corsMiddleware = (res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
};

// Token verification middleware
const verifyToken = (req, res) => {
    const cookies = cookie.parse(req.headers.cookie || '');
    const token = cookies.token;
    if (!token) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'No token provided' }));
        return null;  // Ensures that the request is terminated
    }
    try {
        return jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid token' }));
        return null;  // Ensures that the request is terminated
    }
};

// Initialize the database and start the server
initializeDatabase().then(() => {
    const server = http.createServer(async (req, res) => {
        corsMiddleware(res);
        if (req.method === 'OPTIONS') {
            res.writeHead(204);
            return res.end();
        }

        if (req.url === '/register' && req.method === 'POST') {
            const { email, password, role } = await parseBody(req);
            const hashedPassword = await bcrypt.hash(password, 10);
            try {
                await db.execute('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)', [email, hashedPassword, role || 'user']);
                res.writeHead(201, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'User registered' }));
            } catch (error) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'User registration failed' }));
            }
        } else if (req.url === '/login' && req.method === 'POST') {
            const { email, password } = await parseBody(req);
            try {
                const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
                const user = rows[0];
                if (!user || !(await bcrypt.compare(password, user.password_hash))) {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    return res.end(JSON.stringify({ error: 'Invalid credentials' }));
                }
                const token = createToken(user);
                res.setHeader('Set-Cookie', cookie.serialize('token', token, { httpOnly: true }));
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'Login successful' }));
            } catch (error) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Login failed' }));
            }
        } else if (req.url === '/logout' && req.method === 'POST') {
            // Clear the cookie by setting Max-Age to 0
            res.setHeader('Set-Cookie', cookie.serialize('token', '', { httpOnly: true, maxAge: 0 }));
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ message: 'Logout successful' }));
        } else if (req.url.startsWith('/api/data') && req.method === 'GET') {
            const user = verifyToken(req, res);
            if (!user) return;  // Terminate the request if token verification fails
        
            const [rows] = await db.execute('SELECT * FROM users WHERE id = ?', [user.id]);
            if (rows[0].api_calls >= 20 && user.role !== 'admin') {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ error: 'API call limit exceeded' }));
            }
            
            await db.execute('UPDATE users SET api_calls = api_calls + 1 WHERE id = ?', [user.id]);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ data: 'Protected data for logged in users' }));
        } else {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Route not found' }));
        }
    });

    server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}).catch(error => {
    console.error("Error initializing database:", error);
});
