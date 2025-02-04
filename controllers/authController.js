//ChatGPT helped with the creation of this file

const bcrypt = require('bcryptjs');
const parseBody = require('../utils/parseBody');
const jwt = require('jsonwebtoken');
const jwtHelper = require('../utils/jwtHelper');
const { sendResetCode } = require('../utils/mailer');
const { db, runQuery, getQuery } = require('../utils/dbHelper');
const cookie = require('cookie');
const { incrementApiUsage } = require('./apiController');
const MESSAGE = require('../lang/messages/en/user');
const { validateEmail, validateNumber  } = require('../utils/validation');

const login = async (req, res) => {
    try {
        const { email, password } = await parseBody(req);

        // Input validation
        if (!validateEmail(email) || !password) {
            res.statusCode = 400;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: MESSAGE.errors.invalidJsonFormat }));
            return;
        }

        // Retrieve user and role information
        const user = await getQuery(
            `
            SELECT u.id, u.email, u.password_hash, r.role_name AS role
            FROM users u
            INNER JOIN roles r ON u.role_id = r.id
            WHERE u.email = ?
            `,
            [email]
        );

        // Validate user credentials
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            res.statusCode = 401;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: MESSAGE.errors.invalidCredentials }));
            return;
        }

        // Create JWT token with user ID and role
        const token = jwtHelper.createToken({ id: user.id, role: user.role });
        res.setHeader(
            'Set-Cookie',
            cookie.serialize('jwt', token, {
                httpOnly: true,
                secure: true,
                sameSite: 'None',
                maxAge: 60 * 60,
                path: '/',
            })
        );

        // Increment API usage for login
        incrementApiUsage(MESSAGE.api.login, 'POST', user.id);

        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ message: MESSAGE.messages.loginSuccessful }));
    } catch (error) {
        console.error('Error in login:', error);
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: MESSAGE.errors.invalidJsonFormat }));
    }
};

const register = async (req, res) => {
    try {
        const { email, password, role } = await parseBody(req);

        // Input validation
        if (!validateEmail(email) || !password) {
            res.statusCode = 400;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: MESSAGE.errors.invalidJsonFormat }));
            return;
        }

        // Hash the user's password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Determine role ID from roles table
        const roleResult = await getQuery(
            `
            SELECT id AS role_id
            FROM roles
            WHERE role_name = ?
            `,
            [role || 'user']
        );

        if (!roleResult) {
            res.statusCode = 400;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: MESSAGE.errors.invalidRole }));
            return;
        }

        const roleId = roleResult.role_id;

        // Insert the new user with the corresponding role_id
        await runQuery(
            `
            INSERT INTO users (email, password_hash, role_id)
            VALUES (?, ?, ?)
            `,
            [email, hashedPassword, roleId]
        );

        res.statusCode = 201;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ message: MESSAGE.messages.userRegistered }));
    } catch (error) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: MESSAGE.errors.userRegistrationFailed }));
    }
};

const forgotPassword = async (req, res) => {
    const { email } = await parseBody(req);
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + 15 * 60 * 1000; // 15 minutes

    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, user) => {
        if (err || !user) {
            res.statusCode = 500;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ error: MESSAGE.errors.userNotFound }));
            return;
        }

        incrementApiUsage(MESSAGE.api.forgotPassword, 'POST', user.id);

        db.run(
            'INSERT INTO reset_codes (user_id, reset_code, reset_expires) VALUES (?, ?, ?)',
            [user.id, resetCode, expires],
            async (err) => {
                if (err) {
                    res.statusCode = 500;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ error: MESSAGE.errors.failedToGenerateResetCode }));
                    return;
                }
                
                try {
                    await sendResetCode(email, resetCode);
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ message: MESSAGE.messages.resetCodeSent }));
                } catch (emailError) {
                    res.statusCode = 500;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ error: MESSAGE.errors.failedToSendEmail }));
                }
            }
        );
    });
};

const resetPassword = async (req, res) => {
    const { email, resetCode, newPassword } = await parseBody(req);

    // Input validation
    if (!validateEmail(email) || !validateNumber(resetCode) || !newPassword) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: MESSAGE.errors.invalidJsonFormat }));
        return;
    }

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
                res.statusCode = 400;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({ error: MESSAGE.errors.invalidOrExpiredResetCode }));
                return;
            }

            incrementApiUsage(MESSAGE.api.resetPassword, 'POST', data.user_id);

            bcrypt.hash(newPassword, 10, (hashErr, hashedPassword) => {
                if (hashErr) {
                    res.statusCode = 500;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ error: MESSAGE.errors.failedToHashPassword }));
                    return;
                }

                db.run(
                    'UPDATE users SET password_hash = ? WHERE id = ?',
                    [hashedPassword, data.user_id],
                    (updateErr) => {
                        if (updateErr) {
                            res.statusCode = 500;
                            res.setHeader('Content-Type', 'application/json');
                            res.end(JSON.stringify({ error: MESSAGE.errors.failedToResetPassword }));
                            return;
                        }

                        db.run('DELETE FROM reset_codes WHERE user_id = ?', [data.user_id], (deleteErr) => {
                            if (deleteErr) {
                                console.error('Failed to delete reset code:', deleteErr);
                            }
                        });

                        res.statusCode = 200;
                        res.setHeader('Content-Type', 'application/json');
                        res.end(JSON.stringify({ message: MESSAGE.messages.passwordResetSuccessful }));
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
        res.statusCode = 401;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ authenticated: false, message: MESSAGE.errors.noTokenProvided }));
        return;
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            res.statusCode = 401;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ authenticated: false, message: MESSAGE.errors.invalidToken }));
            return;
        }

        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ authenticated: true, role: decoded.role }));
    });
};


module.exports = { login, register, forgotPassword, resetPassword, validateToken };
