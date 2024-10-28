const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
require('dotenv').config();

async function initializeDatabase() {
    const connection = await mysql.createConnection({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASS,
    });

    // Check if the database exists
    const [databases] = await connection.query("SHOW DATABASES LIKE 'myApp';");

    if (databases.length === 0) {
        console.log("Database not found. Creating database 'myApp'...");

        // Create the database
        await connection.query("CREATE DATABASE myApp;");
        console.log("Database 'myApp' created successfully.");

        // Connect to the new database to create tables
        await connection.changeUser({ database: 'myApp' });

        // Create the users table
        await connection.query(`
            CREATE TABLE users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('user', 'admin') DEFAULT 'user',
                api_calls INT DEFAULT 0
            );
        `);
        console.log("Tables created successfully.");
    } else {
        console.log("Database 'myApp' already exists.");
        await connection.changeUser({ database: 'myApp' });
    }

    // Check if an admin user already exists
    const [rows] = await connection.query("SELECT * FROM users WHERE email = 'admin@admin.com'");
    if (rows.length === 0) {
        // Hash the password
        const adminPassword = '111';
        const hashedPassword = await bcrypt.hash(adminPassword, 10);

        // Insert the admin user
        await connection.query(`
            INSERT INTO users (email, password_hash, role)
            VALUES ('admin@admin.com', ?, 'admin')
        `, [hashedPassword]);
        
        console.log("Admin user created with email 'admin@admin.com'.");
    } else {
        console.log("Admin user already exists.");
    }

    await connection.end();
}

module.exports = initializeDatabase;
