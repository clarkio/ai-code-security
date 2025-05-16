// db.js
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Use DATABASE_URL from environment or default to a local file
const dbPath = process.env.DATABASE_URL || path.join(__dirname, 'notes.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database', err.message);
        process.exit(1); // Exit if DB connection fails
    } else {
        console.log('Connected to the SQLite database.');
        initializeDb();
    }
});

function initializeDb() {
    db.serialize(() => {
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `, (err) => {
            if (err) console.error("Error creating users table", err.message);
        });

        db.run(`
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                userId INTEGER NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
            )
        `, (err) => {
            if (err) console.error("Error creating notes table", err.message);
        });

        // Create an index for faster lookups on userId in notes table
        db.run(`CREATE INDEX IF NOT EXISTS idx_notes_userId ON notes(userId)`, (err) => {
            if (err) console.error("Error creating index on notes(userId)", err.message);
        });
    });
}

module.exports = db;