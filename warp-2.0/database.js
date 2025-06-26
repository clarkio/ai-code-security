const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

class Database {
    constructor() {
        this.db = null;
        this.init();
    }

    init() {
        // Ensure data directory exists
        const dataDir = path.dirname(process.env.DB_PATH || './data/notes.db');
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
        }

        // Initialize database with security settings
        this.db = new sqlite3.Database(process.env.DB_PATH || './data/notes.db', (err) => {
            if (err) {
                console.error('Error opening database:', err.message);
                process.exit(1);
            }
            console.log('Connected to SQLite database');
        });

        // Enable foreign key constraints for data integrity
        this.db.run('PRAGMA foreign_keys = ON');
        
        // Create tables with proper constraints
        this.createTables();
    }

    createTables() {
        // Users table with security constraints
        this.db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL CHECK(length(username) >= 3 AND length(username) <= 50),
                email TEXT UNIQUE NOT NULL CHECK(email LIKE '%@%.%'),
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until DATETIME NULL
            )
        `, (err) => {
            if (err) {
                console.error('Error creating users table:', err);
                return;
            }
            
            // Notes table with user association (create after users table)
            this.db.run(`
                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL CHECK(length(title) >= 1 AND length(title) <= 200),
                    content TEXT NOT NULL CHECK(length(content) <= 10000),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            `, (err) => {
                if (err) {
                    console.error('Error creating notes table:', err);
                    return;
                }
                
                // Create indexes after tables are created
                this.db.run('CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id)', (err) => {
                    if (err && !err.message.includes('already exists')) console.error('Error creating notes index:', err);
                });
                this.db.run('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)', (err) => {
                    if (err && !err.message.includes('already exists')) console.error('Error creating users email index:', err);
                });
                this.db.run('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)', (err) => {
                    if (err && !err.message.includes('already exists')) console.error('Error creating users username index:', err);
                });
            });
        });

        // Session blacklist for logout security (independent table)
        this.db.run(`
            CREATE TABLE IF NOT EXISTS session_blacklist (
                token_jti TEXT PRIMARY KEY,
                expires_at DATETIME NOT NULL
            )
        `, (err) => {
            if (err) console.error('Error creating session_blacklist table:', err);
        });
    }

    // Secure parameterized query methods
    get(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.get(sql, params, (err, row) => {
                if (err) {
                    console.error('Database GET error:', err.message);
                    reject(err);
                } else {
                    resolve(row);
                }
            });
        });
    }

    all(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.all(sql, params, (err, rows) => {
                if (err) {
                    console.error('Database ALL error:', err.message);
                    reject(err);
                } else {
                    resolve(rows);
                }
            });
        });
    }

    run(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.run(sql, params, function(err) {
                if (err) {
                    console.error('Database RUN error:', err.message);
                    reject(err);
                } else {
                    resolve({ id: this.lastID, changes: this.changes });
                }
            });
        });
    }

    close() {
        return new Promise((resolve, reject) => {
            this.db.close((err) => {
                if (err) {
                    reject(err);
                } else {
                    console.log('Database connection closed');
                    resolve();
                }
            });
        });
    }

    // Clean up expired sessions
    cleanupExpiredSessions() {
        const sql = 'DELETE FROM session_blacklist WHERE expires_at < datetime("now")';
        this.run(sql).catch(err => console.error('Error cleaning up expired sessions:', err));
    }
}

module.exports = new Database();
