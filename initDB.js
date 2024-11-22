// ChatGPT helped with the creation of this file

require('dotenv').config();
const { db, queries } = require('./utils/dbHelper');
const bcrypt = require('bcryptjs');

const initializeDatabase = () => {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            console.log("Connected to SQLite database.");

            // Create the roles table and insert default roles
            db.run(queries.createRolesTable, (err) => {
                if (err) {
                    console.error("Error creating roles table:", err.message);
                    reject(err);
                    return;
                }

                db.run(queries.insertDefaultRoles, (err) => {
                    if (err) {
                        console.error("Error inserting default roles:", err.message);
                        // Log but continue (roles might already exist)
                    }

                    // Create the users table
                    db.run(queries.createUsersTable, (err) => {
                        if (err) {
                            console.error("Error creating users table:", err.message);
                            reject(err);
                            return;
                        }

                        // Create the reset_codes table
                        db.run(queries.createResetCodesTable, (err) => {
                            if (err) {
                                console.error("Error creating reset_codes table:", err.message);
                                reject(err);
                                return;
                            }

                            // Create the wav_files table
                            db.run(queries.createWavFileTable, (err) => {
                                if (err) {
                                    console.error("Error creating wav_files table:", err.message);
                                    reject(err);
                                    return;
                                }

                                // Create the api_usage_logs table
                                db.run(queries.createApiCallsTable, (err) => {
                                    if (err) {
                                        console.error("Error creating api_usage_logs table:", err.message);
                                        reject(err);
                                        return;
                                    }

                                    // Check if the admin user exists
                                    const adminEmail = process.env.ADMIN_EMAIL;
                                    const adminPassword = process.env.ADMIN_PASSWORD;
                                    const sampleUserEmail = process.env.USER_EMAIL;
                                    const sampleUserPassword = process.env.USER_PASSWORD;

                                    db.get(queries.checkAdminExists, [adminEmail], async (err, adminRow) => {
                                        if (err) {
                                            console.error("Error querying admin user:", err.message);
                                            reject(err);
                                            return;
                                        }

                                        if (!adminRow) {
                                            try {
                                                const hashedAdminPassword = await bcrypt.hash(adminPassword, 10);
                                                db.run(queries.insertAdminUser, [adminEmail, hashedAdminPassword], (err) => {
                                                    if (err) {
                                                        reject(err);
                                                        return;
                                                    }
                                                });
                                            } catch (hashError) {
                                                reject(hashError);
                                                return;
                                            }
                                        }

                                        // Check if the sample user exists
                                        db.get(queries.checkUserExists, [sampleUserEmail], async (err, userRow) => {
                                            if (err) {
                                                console.error("Error querying sample user:", err.message);
                                                reject(err);
                                                return;
                                            }

                                            if (!userRow) {
                                                try {
                                                    const hashedSamplePassword = await bcrypt.hash(sampleUserPassword, 10);
                                                    db.run(queries.insertSampleUser, [sampleUserEmail, hashedSamplePassword], (err) => {
                                                        if (err) {
                                                            reject(err);
                                                        } else {
                                                            resolve();
                                                        }
                                                    });
                                                } catch (hashError) {
                                                    reject(hashError);
                                                }
                                            } else {
                                                resolve();
                                            }
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    });
};

module.exports = initializeDatabase;
