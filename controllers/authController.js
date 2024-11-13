//ChatGPT helped with the creation of this file

const bcrypt = require('bcryptjs');
const parseBody = require('../utils/parseBody');
const jwt = require('jsonwebtoken');
const jwtHelper = require('../utils/jwtHelper');
const { sendResetCode } = require('../utils/mailer');
const { db, runQuery, getQuery } = require('../utils/dbHelper');
const cookie = require('cookie');

// Login function
const login = async (req, res) => {
    try {
        const { email, password } = await parseBody(req); // Parse body here
        const user = await getQuery('SELECT * FROM users WHERE email = ?', [email]);

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            res.statusCode = 401;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: 'Invalid credentials' }));
            return;
        } 

            const token = jwtHelper.createToken({ id: user.id, role: user.role });
            res.setHeader('Set-Cookie', cookie.serialize('jwt', token, {
                httpOnly: true,
                secure: true,
                sameSite: 'None',
                //for local testing
                // httpOnly: false,
                // secure: false,
                // sameSite: 'Lax',
                path: '/',
            }));
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ message: 'Login successful' }));
        } catch (error) {
            console.error('Error in login:', error);
            res.statusCode = 400;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: 'Invalid JSON format' }));
        }
    };

const register = async (req, res) => {
    try {
        const { email, password, role } = await parseBody(req);
        const hashedPassword = await bcrypt.hash(password, 10);
        
        await runQuery('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)', [email, hashedPassword, role || 'user']);
        
        res.statusCode = 201;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ message: 'User registered' }));
    } catch (error) {
        console.error('Error in register:', error);
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'User registration failed' }));
    }
};

const forgotPassword = async (req, res) => {
    const { email } = await parseBody(req);

    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + 15 * 60 * 1000; // 15 minutes

    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, user) => {
        if (err || !user) {
            console.error('Database error or user not found:', err);
            res.statusCode = 500;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: 'User not found' }));
            return;
        }

        db.run(
            `INSERT INTO reset_codes (user_id, reset_code, reset_expires) VALUES (?, ?, ?)`,
            [user.id, resetCode, expires],
            async (err) => {
                if (err) {
                    console.error('Database insert error:', err);
                    res.statusCode = 500;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ error: 'Failed to generate reset code' }));
                    return;
                }
                try {
                    await sendResetCode(email, resetCode);
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ message: 'Reset code sent to email' }));
                } catch (emailError) {
                    res.statusCode = 500;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ error: 'Failed to send email' }));
                }
            }
        );
    });
};

const resetPassword = async (req, res) => {
    const { email, resetCode, newPassword } = await parseBody(req);

    db.get(
        `
        SELECT users.id AS user_id, reset_codes.reset_code, reset_codes.reset_expires
        FROM users
        JOIN reset_codes ON users.id = reset_codes.user_id
        WHERE users.email = ? AND reset_codes.reset_code = ?
    `,
        [email, resetCode],
        (err, data) => {
            if (err || !data || data.reset_expires < Date.now()) {
                console.error('Invalid or expired reset code:', err);
                res.statusCode = 400;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({ error: 'Invalid or expired reset code' }));
                return;
            }

            bcrypt.hash(newPassword, 10, (hashErr, hashedPassword) => {
                if (hashErr) {
                    console.error('Hashing error:', hashErr);
                    res.statusCode = 500;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ error: 'Failed to hash password' }));
                    return;
                }

                db.run(
                    'UPDATE users SET password_hash = ? WHERE id = ?',
                    [hashedPassword, data.user_id],
                    (updateErr) => {
                        if (updateErr) {
                            console.error('Database update error:', updateErr);
                            res.statusCode = 500;
                            res.setHeader('Content-Type', 'application/json');
                            res.end(JSON.stringify({ error: 'Failed to reset password' }));
                            return;
                        }

                        db.run('DELETE FROM reset_codes WHERE user_id = ?', [data.user_id], (deleteErr) => {
                            if (deleteErr) {
                                console.error('Failed to delete reset code:', deleteErr);
                            }
                        });

                        res.statusCode = 200;
                        res.setHeader('Content-Type', 'application/json');
                        res.end(JSON.stringify({ message: 'Password reset successfully' }));
                    }
                );
            });
        }
    );
};

const validateToken = (req, res) => {
    const cookies = req.headers.cookie
        ?.split(';')
        .map(cookie => cookie.trim().split('='))
        .reduce((acc, [key, value]) => ({ ...acc, [key]: decodeURIComponent(value) }), {});

    const token = cookies?.jwt;

    if (!token) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ authenticated: false, message: 'No token provided' }));
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ authenticated: false, message: 'Invalid token' }));
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ authenticated: true, role: decoded.role }));
    });
};

module.exports = { login, register, forgotPassword, resetPassword, validateToken };
