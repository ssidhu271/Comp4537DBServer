//ChatGPT helped with the creation of this file

const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.resolve(__dirname, '../Comp4537Database.db');
const db = new sqlite3.Database(dbPath);

const queries = {
    createRolesTable: `
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role_name TEXT UNIQUE NOT NULL
        )
    `,
    insertDefaultRoles: `
        INSERT OR IGNORE INTO roles (role_name) VALUES ('admin'), ('user')
    `,
    createUsersTable: `
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role_id INTEGER NOT NULL,
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE SET NULL
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
    checkAdminExists: `
        SELECT u.* 
        FROM users u
        INNER JOIN roles r ON u.role_id = r.id
        WHERE u.email = ? AND r.role_name = 'admin'
    `,
    insertAdminUser: `
        INSERT INTO users (email, password_hash, role_id)
        VALUES (?, ?, (SELECT id FROM roles WHERE role_name = 'admin'))
    `,
    createWavFileTable: `
        CREATE TABLE IF NOT EXISTS wav_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            file_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            updated_at INTEGER DEFAULT (strftime('%s', 'now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `,
    insertWavFile: `
        INSERT INTO wav_files (user_id, file_name, file_path) 
        VALUES (?, ?, ?)
    `,
    updateWavFileName: `
        UPDATE wav_files SET file_name = ?, updated_at = (strftime('%s', 'now')) 
        WHERE id = ? AND user_id = ?
    `,
    deleteWavFile: `
        DELETE FROM wav_files WHERE id = ? AND user_id = ?
    `,
    getWavFilesByUser: `
        SELECT * FROM wav_files WHERE user_id = ?
    `,
    createApiCallsTable: `
        CREATE TABLE IF NOT EXISTS api_usage_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            endpoint TEXT NOT NULL,
            method TEXT NOT NULL,
            request_count INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, endpoint, method) -- Unique constraint per user
        )
    `,
    checkUserExists: `
    SELECT u.* 
    FROM users u
    WHERE u.email = ?
    `,
    insertSampleUser: `
        INSERT INTO users (email, password_hash, role_id)
        VALUES (?, ?, (SELECT id FROM roles WHERE role_name = 'user'))
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
