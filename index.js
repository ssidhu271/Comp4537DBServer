// index.js
const http = require('http');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookie = require('cookie');
const initializeDatabase = require('./initDB'); // Import the DB initialization module
const PORT = process.env.PORT || 8888;
const nodemailer = require('nodemailer');
require('dotenv').config();

// Connect to the SQLite database
const db = new sqlite3.Database('./myApp.db');

// Helper to create JWT tokens
const createToken = (user) => jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

// Helper to parse JSON requests
const parseBody = (req) => new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => {
        try {
            resolve(JSON.parse(body));
        } catch (error) {
            reject(error);
        }
    });
    req.on('error', reject);
});


const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465, // Secure SMTP port for Gmail
    secure: true, // Use SSL
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
    logger: true, // Add this
    debug: true,  // And this
  });

  const sendResetCode = async (email, resetCode) => {
    const mailOptions = {
      from: `"Your App Name" <${process.env.EMAIL_USER}>`, // Better to specify a name
      to: email,
      subject: 'Password Reset Code',
      text: `Your password reset code is: ${resetCode}`,
    };
  
    try {
      const info = await transporter.sendMail(mailOptions);
      console.log('Email sent: ', info.response);
    } catch (error) {
      console.error('Error sending email: ', error);
      throw new Error('Failed to send email');
    }
  };

// Middleware to handle CORS and OPTIONS requests
const corsMiddleware = (res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
};

// Token verification middleware
const verifyToken = (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

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
                        [resetCode, Date.now() + 15 * 60 * 1000, email], (err) => { // 15-minute expiry
                        if (err) {
                            console.error('Database update error:', err);
                            res.writeHead(500, { 'Content-Type': 'application/json' });
                            return res.end(JSON.stringify({ error: 'Failed to generate reset code' }));
                        }
                        try {
                            sendResetCode(email, resetCode);
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
                
                    db.get('SELECT reset_code, reset_expires FROM users WHERE email = ?', [email], (err, user) => {
                        if (err) {
                            console.error('Database error:', err);
                            res.writeHead(500, { 'Content-Type': 'application/json' });
                            return res.end(JSON.stringify({ error: 'Database error' }));
                        }
                
                        if (!user || user.reset_code !== resetCode || user.reset_expires < Date.now()) {
                            res.writeHead(400, { 'Content-Type': 'application/json' });
                            return res.end(JSON.stringify({ error: 'Invalid or expired reset code' }));
                        }
                
                        // Reset the password
                        bcrypt.hash(newPassword, 10, (hashErr, hashedPassword) => {
                            if (hashErr) {
                                console.error('Hashing error:', hashErr);
                                res.writeHead(500, { 'Content-Type': 'application/json' });
                                return res.end(JSON.stringify({ error: 'Failed to hash password' }));
                            }
                
                            db.run('UPDATE users SET password_hash = ?, reset_code = NULL, reset_expires = NULL WHERE email = ?', 
                                [hashedPassword, email], (updateErr) => {
                                if (updateErr) {
                                    console.error('Database update error:', updateErr);
                                    res.writeHead(500, { 'Content-Type': 'application/json' });
                                    res.end(JSON.stringify({ error: 'Failed to reset password' }));
                                } else {
                                    res.writeHead(200, { 'Content-Type': 'application/json' });
                                    res.end(JSON.stringify({ message: 'Password reset successfully' }));
                                }
                            });
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
                    // Send token in response, don't set httpOnly cookie
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'Login successful', token }));
                }
            });
        } else if (req.url.startsWith('/api/data') && req.method === 'GET') {
            const user = verifyToken(req, res); // Use verifyToken to extract and verify the JWT
            if (!user) return; // If token verification failed, verifyToken already handled the response
        
            db.get('SELECT * FROM users WHERE id = ?', [user.id], (err, row) => {
                if (err || !row) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Failed to retrieve user data' }));
                    return;
                }
        
                // If user is an admin, return all users' API call counts
                if (row.role === 'admin') {
                    db.all('SELECT email, api_calls FROM users', (adminErr, allUsers) => {
                        if (adminErr) {
                            res.writeHead(500, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ error: 'Failed to retrieve users data' }));
                        } else {
                            res.writeHead(200, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ data: allUsers }));
                        }
                    });
                } else {
                    // Regular user: only show their own API call count
                    const userExceededLimit = row.api_calls >= 20;
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        api_calls: row.api_calls,
                        message: userExceededLimit ? 'API call limit exceeded' : 'API calls within limit'
                    }));
                }
            });
        } else if (req.url === '/api/increment-api-call' && req.method === 'POST') {
            const token = req.headers['authorization'];
            if (!token) {
                res.writeHead(401, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ error: 'Unauthorized access' }));
            }
        
            let user;
            try {
                user = jwt.verify(token, process.env.JWT_SECRET);
            } catch (err) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ error: 'Invalid token' }));
            }
        
            db.get('SELECT * FROM users WHERE id = ?', [user.id], (err, row) => {
                if (err || !row) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Failed to retrieve user data' }));
                    return;
                }
        
                // Only proceed to increment if the user has not exceeded 20 calls or is an admin
                if (row.api_calls < 20 || row.role === 'admin') {
                    db.run('UPDATE users SET api_calls = api_calls + 1 WHERE id = ?', [user.id], (updateErr) => {
                        if (updateErr) {
                            res.writeHead(500, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ error: 'Failed to increment API calls' }));
                        } else {
                            res.writeHead(200, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ message: 'API call incremented successfully' }));
                        }
                    });
                } else {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ warning: 'API call limit exceeded' }));
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
