//ChatGPT helped with the creation of this file

const jwt = require('jsonwebtoken');
const cookie = require('cookie');
require('dotenv').config();

const createToken = (user) => {
    return jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

const verifyToken = (token) => {
    return new Promise((resolve, reject) => {
        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) reject(err);
            else resolve(decoded);
        });
    });
};

module.exports = { createToken, verifyToken };
