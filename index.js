// index.js
const http = require('http');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookie = require('cookie');
const initializeDatabase = require('./initDB'); // Import the DB initialization module
const PORT = process.env.PORT || 8888;
require('dotenv').config();

// Connect to the SQLite database
const db = new sqlite3.Database('./myApp.db');

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
        return null;
    }
    try {
        return jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid token' }));
        return null;
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
                // Forgot Password - Step 1: Generate and send reset code
                if (req.url === '/forgot-password' && req.method === 'POST') {
                    const { email } = await parseBody(req);
        
                    // Generate a reset code
                    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
                    
                    // Store reset code in database (you may want to add a reset_code and reset_expires fields to your users table)
                    db.run('UPDATE users SET reset_code = ?, reset_expires = ? WHERE email = ?', 
                        [resetCode, Date.now() + 15 * 60 * 1000, email], async (err) => { // 15-minute expiry
                        if (err) {
                            res.writeHead(500, { 'Content-Type': 'application/json' });
                            return res.end(JSON.stringify({ error: 'Failed to generate reset code' }));
                        }
                        try {
                            await sendResetCode(email, resetCode);
                            res.writeHead(200, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ message: 'Reset code sent to email' }));
                        } catch (emailError) {
                            res.writeHead(500, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ error: 'Failed to send email' }));
                        }
                    });
                }
        
                // Forgot Password - Step 2: Verify reset code and reset password
                else if (req.url === '/reset-password' && req.method === 'POST') {
                    const { email, resetCode, newPassword } = await parseBody(req);
        
                    // Verify reset code and expiration
                    db.get('SELECT reset_code, reset_expires FROM users WHERE email = ?', [email], async (err, user) => {
                        if (err || !user || user.reset_code !== resetCode || user.reset_expires < Date.now()) {
                            res.writeHead(400, { 'Content-Type': 'application/json' });
                            return res.end(JSON.stringify({ error: 'Invalid or expired reset code' }));
                        }
        
                        // Reset the password
                        const hashedPassword = await bcrypt.hash(newPassword, 10);
                        db.run('UPDATE users SET password_hash = ?, reset_code = NULL, reset_expires = NULL WHERE email = ?', 
                            [hashedPassword, email], (updateErr) => {
                            if (updateErr) {
                                res.writeHead(500, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ error: 'Failed to reset password' }));
                            } else {
                                res.writeHead(200, { 'Content-Type': 'application/json' });
                                res.end(JSON.stringify({ message: 'Password reset successfully' }));
                            }
                        });
                    });
                } else if (req.url === '/register' && req.method === 'POST') {
            const { email, password, role } = await parseBody(req);
            const hashedPassword = await bcrypt.hash(password, 10);
            db.run('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)', [email, hashedPassword, role || 'user'], (err) => {
                if (err) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'User registration failed' }));
                } else {
                    res.writeHead(201, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'User registered' }));
                }
            });
        } else if (req.url === '/login' && req.method === 'POST') {
            const { email, password } = await parseBody(req);
            db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
                if (err || !user || !(await bcrypt.compare(password, user.password_hash))) {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Invalid credentials' }));
                } else {
                    const token = createToken(user);
                    res.setHeader('Set-Cookie', cookie.serialize('token', token, { httpOnly: true }));
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'Login successful' }));
                }
            });
        } else if (req.url.startsWith('/api/data') && req.method === 'GET') {
            const user = verifyToken(req, res);
            if (!user) return;

            db.get('SELECT * FROM users WHERE id = ?', [user.id], (err, row) => {
                if (err || !row || (row.api_calls >= 20 && row.role !== 'admin')) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'API call limit exceeded' }));
                } else {
                    db.run('UPDATE users SET api_calls = api_calls + 1 WHERE id = ?', [user.id], (err) => {
                        if (err) {
                            res.writeHead(500, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ error: 'Failed to update API calls' }));
                        } else {
                            res.writeHead(200, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ data: 'Protected data for logged in users' }));
                        }
                    });
                }
            });
        } else {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Route not found' }));
        }
    });

    server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}).catch(error => {
    console.error("Error initializing database:", error);
});
