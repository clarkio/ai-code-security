const sqlite3 = require('sqlite3').verbose();
require('dotenv').config();

let dbPath = process.env.DATABASE_URL || './notes.sqlite';
if (process.env.NODE_ENV === 'test') {
    dbPath = ':memory:'; // Use in-memory SQLite for tests
    console.log('Using in-memory SQLite database for tests.');
}

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error connecting to SQLite database:', err.message, 'Path:', dbPath);
        // Consider whether to throw the error or exit, depending on application needs
        // For now, we log and the app might continue if db is not critical at startup for all parts.
    } else {
        console.log(`Connected to SQLite database at ${dbPath}.`);
    }
});

// Optional: Enable foreign key constraints
db.run("PRAGMA foreign_keys = ON;", (err) => {
    if (err) {
        console.error("Failed to enable foreign key constraints:", err.message);
    } else {
        if (process.env.NODE_ENV !== 'test') { // Reduce noise during tests
            console.log("Foreign key constraints enabled.");
        }
    }
});

module.exports = db;
