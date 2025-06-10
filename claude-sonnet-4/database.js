const sqlite3 = require('sqlite3').verbose()
const path = require('path')
const fs = require('fs')

class Database {
  constructor () {
    this.db = null
    this.dbPath = process.env.DB_PATH || './data/notes.db'
  }

  async initialize () {
    try {
      // Ensure data directory exists
      const dataDir = path.dirname(this.dbPath)
      if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true })
      }

      // Initialize database connection
      this.db = new sqlite3.Database(this.dbPath, (err) => {
        if (err) {
          console.error('Error opening database:', err)
          throw err
        }
        console.log('Connected to SQLite database')
      })

      // Enable foreign key constraints
      await this.run('PRAGMA foreign_keys = ON')

      // Create tables
      await this.createTables()

      return this.db
    } catch (error) {
      console.error('Database initialization error:', error)
      throw error
    }
  }

  async createTables () {
    const createUsersTable = `
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until DATETIME NULL
      )
    `

    const createNotesTable = `
      CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )
    `

    const createSessionsTable = `
      CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY,
        sess TEXT NOT NULL,
        expired INTEGER NOT NULL
      )
    `

    // Create indexes for performance
    const createIndexes = [
      'CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)',
      'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)',
      'CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_sessions_expired ON sessions(expired)'
    ]

    try {
      await this.run(createUsersTable)
      await this.run(createNotesTable)
      await this.run(createSessionsTable)

      for (const indexQuery of createIndexes) {
        await this.run(indexQuery)
      }

      console.log('Database tables created successfully')
    } catch (error) {
      console.error('Error creating tables:', error)
      throw error
    }
  }

  // Promisify database operations
  run (sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, function (err) {
        if (err) {
          reject(err)
        } else {
          resolve({ id: this.lastID, changes: this.changes })
        }
      })
    })
  }

  get (sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.get(sql, params, (err, row) => {
        if (err) {
          reject(err)
        } else {
          resolve(row)
        }
      })
    })
  }

  all (sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) {
          reject(err)
        } else {
          resolve(rows)
        }
      })
    })
  }

  close () {
    return new Promise((resolve, reject) => {
      if (this.db) {
        this.db.close((err) => {
          if (err) {
            reject(err)
          } else {
            console.log('Database connection closed')
            resolve()
          }
        })
      } else {
        resolve()
      }
    })
  }
}

module.exports = new Database()
