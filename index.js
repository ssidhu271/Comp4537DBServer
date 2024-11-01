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
      from: `"Grey Dune" <${process.env.EMAIL_USER}>`, // Better to specify a name
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

// Token verification middleware
const verifyToken = (req, res) => {
    const cookies = cookie.parse(req.headers.cookie || '');
    const token = cookies.jwt; // Read the JWT from the cookie

    if (!token) {
        res.statusCode = 401;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'No token provided' }));
        return null;
    }

    try {
        return jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
        console.error('JWT verification error:', error);
        res.statusCode = 403;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Invalid token' }));
        return null;
    }
};

// Initialize the database and start the server
initializeDatabase().then(() => {
    const server = http.createServer(async (req, res) => {
        const allowedOrigin = 'https://gray-dune-0c3966f1e.5.azurestaticapps.net';
        const origin = req.headers.origin;
        if (origin === allowedOrigin) {
            res.setHeader('Access-Control-Allow-Origin', origin);
        }
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');   
        // Handle OPTIONS preflight request
        if (req.method === 'OPTIONS') {
            res.writeHead(204);
            return res.end();
        }        
                // Forgot Password - Step 1: Generate and send reset code
                if (req.url === '/forgot-password' && req.method === 'POST') {
                    const { email } = await parseBody(req);
                
                    // Generate a reset code
                    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
                    const expires = Date.now() + 15 * 60 * 1000; // 15-minute expiry
                
                    // Fetch user ID based on the email
                    db.get('SELECT id FROM users WHERE email = ?', [email], (err, user) => {
                        if (err || !user) {
                            console.error('Database error or user not found:', err);
                            res.statusCode = 500;
                            res.setHeader('Content-Type', 'application/json');
                            return res.end(JSON.stringify({ error: 'User not found' }));
                        }
                
                        // Insert reset code into reset_codes table
                        db.run(`
                            INSERT INTO reset_codes (user_id, reset_code, reset_expires)
                            VALUES (?, ?, ?)
                        `, [user.id, resetCode, expires], (err) => {
                            if (err) {
                                console.error('Database insert error:', err);
                                res.statusCode = 500;
                                res.setHeader('Content-Type', 'application/json');
                                return res.end(JSON.stringify({ error: 'Failed to generate reset code' }));
                            }
                            try {
                                sendResetCode(email, resetCode);
                                res.statusCode = 200;
                                res.setHeader('Content-Type', 'application/json');
                                res.end(JSON.stringify({ message: 'Reset code sent to email' }));
                            } catch (emailError) {
                                res.statusCode = 500;
                                res.setHeader('Content-Type', 'application/json');
                                res.end(JSON.stringify({ error: 'Failed to send email' }));
                            }
                        });
                    });
                }
                
                // Forgot Password - Step 2: Verify reset code and reset password
                else if (req.url === '/reset-password' && req.method === 'POST') {
                    const { email, resetCode, newPassword } = await parseBody(req);
                
                    // Retrieve user ID and reset code details
                    db.get(`
                        SELECT users.id AS user_id, reset_codes.reset_code, reset_codes.reset_expires
                        FROM users
                        JOIN reset_codes ON users.id = reset_codes.user_id
                        WHERE users.email = ? AND reset_codes.reset_code = ?
                    `, [email, resetCode], (err, data) => {
                        if (err || !data || data.reset_expires < Date.now()) {
                            res.statusCode = 400;
                            res.setHeader('Content-Type', 'application/json');
                            return res.end(JSON.stringify({ error: 'Invalid or expired reset code' }));
                        }
                
                        // Reset the password
                        bcrypt.hash(newPassword, 10, (hashErr, hashedPassword) => {
                            if (hashErr) {
                                console.error('Hashing error:', hashErr);
                                res.statusCode = 500;
                                res.setHeader('Content-Type', 'application/json');
                                return res.end(JSON.stringify({ error: 'Failed to hash password' }));
                            }
                
                            // Update the password and remove reset code entries
                            db.run('UPDATE users SET password_hash = ? WHERE id = ?', [hashedPassword, data.user_id], (updateErr) => {
                                if (updateErr) {
                                    console.error('Database update error:', updateErr);
                                    res.statusCode = 500;
                                    res.setHeader('Content-Type', 'application/json');
                                    return res.end(JSON.stringify({ error: 'Failed to reset password' }));
                                }
                
                                // Delete the used reset code from reset_codes
                                db.run('DELETE FROM reset_codes WHERE user_id = ?', [data.user_id], (deleteErr) => {
                                    if (deleteErr) {
                                        console.error('Failed to delete reset code:', deleteErr);
                                    }
                                });
                
                                res.statusCode = 200;
                                res.setHeader('Content-Type', 'application/json');
                                res.end(JSON.stringify({ message: 'Password reset successfully' }));
                            });
                        });
                    });
                } else if (req.url === '/register' && req.method === 'POST') {
            const { email, password, role } = await parseBody(req);
            const hashedPassword = await bcrypt.hash(password, 10);
            db.run('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)', [email, hashedPassword, role || 'user'], (err) => {
                if (err) {
                    res.statusCode = 500;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ error: 'User registration failed' }));
                } else {
                    res.statusCode = 201;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ message: 'User registered' }));
                }
            });
        } else if (req.url === '/login' && req.method === 'POST') {
            const { email, password } = await parseBody(req);
            db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
                if (err || !user || !(await bcrypt.compare(password, user.password_hash))) {
                    res.statusCode = 401;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ error: 'Invalid credentials' }));
                } else {
                    const token = createToken(user);
                    res.setHeader('Set-Cookie', cookie.serialize('jwt', token, {
                        httpOnly: false,
                        secure: true,
                        maxAge: 60 * 60,
                        sameSite: 'None', //change to None for cross-site cookies
                        path: '/',
                    }));
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ message: 'Login successful'}));
                }
            });
        } else if (req.url === '/api/user-data' && req.method === 'GET') {
            const user = verifyToken(req, res);
            if (!user) return; // Token verification failed; response handled by verifyToken
        
            db.get('SELECT * FROM users WHERE id = ?', [user.id], (err, row) => {
                if (err || !row) {
                    res.statusCode = 500;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ error: 'Failed to retrieve user data' }));
                    return;
                }
        
                const userExceededLimit = row.api_calls >= 20;
                res.statusCode = 200;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({
                    api_calls: row.api_calls,
                    message: userExceededLimit ? 'API call limit exceeded' : 'API calls within limit',
                    status: userExceededLimit ? 'warning' : 'ok'
                }));
            });
        } else if (req.url === '/api/admin-data' && req.method === 'GET') {
            const user = verifyToken(req, res);
            if (!user) return;
        
            // Check if user is an admin
            db.get('SELECT * FROM users WHERE id = ?', [user.id], (err, row) => {
                if (err || !row || row.role !== 'admin') {
                    res.statusCode = 403;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ error: 'Access denied' }));
                    return;
                }
        
                // Fetch all users' API calls if the user is an admin
                db.all('SELECT email, api_calls FROM users', (adminErr, allUsers) => {
                    if (adminErr) {
                        res.statusCode = 500;
                        res.setHeader('Content-Type', 'application/json');
                        res.end(JSON.stringify({ error: 'Failed to retrieve users data' }));
                    } else {
                        res.statusCode = 200;
                        res.setHeader('Content-Type', 'application/json');
                        res.end(JSON.stringify({ data: allUsers }));
                    }
                });
            });
        } else if (req.url === '/api/increment-api-call' && req.method === 'POST') {
            const user = verifyToken(req, res);
            if (!user) return;
        
            db.get('SELECT * FROM users WHERE id = ?', [user.id], (err, row) => {
                if (err || !row) {
                    res.statusCode = 500;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ error: 'Failed to retrieve user data' }));
                    return;
                }
        
                // Only proceed to increment if the user has not exceeded 20 calls or is an admin
                if (row.api_calls < 20 || row.role === 'admin') {
                    db.run('UPDATE users SET api_calls = api_calls + 1 WHERE id = ?', [user.id], (updateErr) => {
                        if (updateErr) {
                            res.statusCode = 500;
                            res.setHeader('Content-Type', 'application/json');
                            res.end(JSON.stringify({ error: 'Failed to increment API calls' }));
                        } else {
                            res.statusCode = 200;
                            res.setHeader('Content-Type', 'application/json');
                            res.end(JSON.stringify({ message: 'API call incremented successfully' }));
                        }
                    });
                } else {
                    res.statusCode = 403;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ warning: 'API call limit exceeded' }));
                }
            });
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
