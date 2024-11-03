const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Define the path to your database
const dbPath = path.resolve(__dirname, '../myApp.db');
const db = new sqlite3.Database(dbPath);

// SQL Queries
const queries = {
    createUsersTable: `
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            api_calls INTEGER DEFAULT 0
        )
    `,
    createResetCodesTable: `
        CREATE TABLE IF NOT EXISTS reset_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            reset_code TEXT NOT NULL,
            reset_expires INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `,
    checkAdminExists: "SELECT * FROM users WHERE email = ?",
    insertAdminUser: `
        INSERT INTO users (email, password_hash, role)
        VALUES (?, ?, 'admin')
    `,
};

// Function to run queries (insert, update, delete) with parameters
const runQuery = (query, params = []) => {
    return new Promise((resolve, reject) => {
        db.run(query, params, function (err) {
            if (err) reject(err);
            else resolve(this); // `this` contains information about the last operation, like lastID
        });
    });
};

// Function to get a single row
const getQuery = (query, params = []) => {
    return new Promise((resolve, reject) => {
        db.get(query, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
};

// Function to get all rows
const allQuery = (query, params = []) => {
    return new Promise((resolve, reject) => {
        db.all(query, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
};

// Export the database instance, query functions, and queries
module.exports = { db, runQuery, getQuery, allQuery, queries };
