const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

// Define the database file location
const dbPath = path.resolve(__dirname, 'myApp.db');

// Function to initialize the database
function initializeDatabase() {
    return new Promise((resolve, reject) => {
        const db = new sqlite3.Database(dbPath, (err) => {
            if (err) {
                console.error("Error opening database:", err.message);
                reject(err);
                return;
            }
            console.log("Connected to SQLite database.");

            // Create the users table if it doesn't exist
            db.run(`
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    api_calls INTEGER DEFAULT 0
                )
            `, (err) => {
                if (err) {
                    console.error("Error creating table:", err.message);
                    reject(err);
                    return;
                }

                // Check if the admin user exists and create one if not
                const adminEmail = 'admin@admin.com';
                const adminPassword = '111';
                db.get("SELECT * FROM users WHERE email = ?", [adminEmail], async (err, row) => {
                    if (err) {
                        console.error("Error querying admin user:", err.message);
                        reject(err);
                        return;
                    }

                    if (!row) {
                        // Hash the admin password and insert the admin user
                        const hashedPassword = await bcrypt.hash(adminPassword, 10);
                        db.run(`
                            INSERT INTO users (email, password_hash, role)
                            VALUES (?, ?, 'admin')
                        `, [adminEmail, hashedPassword], (err) => {
                            if (err) {
                                console.error("Error creating admin user:", err.message);
                                reject(err);
                            } else {
                                console.log("Admin user created with email 'admin@admin.com'.");
                                resolve();
                            }
                        });
                    } else {
                        console.log("Admin user already exists.");
                        resolve();
                    }
                });
            });
        });
    });
}

module.exports = initializeDatabase;
