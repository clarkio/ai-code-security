// db.js - Secure SQLite DB layer
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const DBSOURCE = path.join(__dirname, 'notes.sqlite');

const db = new sqlite3.Database(DBSOURCE, (err) => {
  if (err) throw err;
});

// Create users and notes tables if not exist
const userTable = `CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
)`;
const notesTable = `CREATE TABLE IF NOT EXISTS notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
)`;
db.serialize(() => {
  db.run(userTable);
  db.run(notesTable);
});

module.exports = db;
