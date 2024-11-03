require('dotenv').config();
const { db, queries } = require('./utils/dbHelper'); // Import the shared db instance
const bcrypt = require('bcryptjs');

// Function to initialize the database
function initializeDatabase() {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            console.log("Connected to SQLite database.");

            // Create the users table
            db.run(queries.createUsersTable, (err) => {
                if (err) {
                    console.error("Error creating users table:", err.message);
                    reject(err);
                    return;
                }

                // Create the reset_codes table
                db.run(queries.createResetCodesTable, async (err) => {
                    if (err) {
                        console.error("Error creating reset_codes table:", err.message);
                        reject(err);
                        return;
                    }

                    // Check if the admin user exists
                    const adminEmail = process.env.ADMIN_EMAIL;
                    const adminPassword = process.env.ADMIN_PASSWORD;
                    db.get(queries.checkAdminExists, [adminEmail], async (err, row) => {
                        if (err) {
                            console.error("Error querying admin user:", err.message);
                            reject(err);
                            return;
                        }

                        if (!row) {
                            try {
                                const hashedPassword = await bcrypt.hash(adminPassword, 10);
                                db.run(queries.insertAdminUser, [adminEmail, hashedPassword], (err) => {
                                    if (err) {
                                        console.error("Error creating admin user:", err.message);
                                        reject(err);
                                    } else {
                                        console.log("Admin user created with email 'admin@admin.com'.");
                                        resolve();
                                    }
                                });
                            } catch (hashError) {
                                console.error("Error hashing admin password:", hashError.message);
                                reject(hashError);
                            }
                        } else {
                            console.log("Admin user already exists.");
                            resolve();
                        }
                    });
                });
            });
        });
    });
}

module.exports = initializeDatabase;
