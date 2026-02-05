const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', 'notes.db');

let db;

async function initDatabase() {
  const SQL = await initSqlJs();

  // Load existing database from disk if it exists
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  // Enable foreign key constraints
  db.run('PRAGMA foreign_keys = ON;');

  // Create tables
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    )
  `);

  db.run('CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id)');

  saveToFile();
  return db;
}

function saveToFile() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

// All user input goes through parameters (?) - NEVER string concatenation.
const queries = {
  createUser(email, passwordHash) {
    db.run('INSERT INTO users (email, password_hash) VALUES (?, ?)', [email, passwordHash]);
    const result = db.exec('SELECT last_insert_rowid() as id');
    saveToFile();
    return result[0].values[0][0];
  },

  getUserByEmail(email) {
    const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
    stmt.bind([email]);
    let user = null;
    if (stmt.step()) {
      user = stmt.getAsObject();
    }
    stmt.free();
    return user;
  },

  getUserById(id) {
    const stmt = db.prepare('SELECT id, email, created_at FROM users WHERE id = ?');
    stmt.bind([id]);
    let user = null;
    if (stmt.step()) {
      user = stmt.getAsObject();
    }
    stmt.free();
    return user;
  },

  createNote(userId, title, content) {
    db.run('INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)', [userId, title, content]);
    saveToFile();
  },

  getNotesByUser(userId) {
    const stmt = db.prepare('SELECT * FROM notes WHERE user_id = ? ORDER BY updated_at DESC');
    stmt.bind([userId]);
    const notes = [];
    while (stmt.step()) {
      notes.push(stmt.getAsObject());
    }
    stmt.free();
    return notes;
  },

  getNoteById(id) {
    const stmt = db.prepare('SELECT * FROM notes WHERE id = ?');
    stmt.bind([id]);
    let note = null;
    if (stmt.step()) {
      note = stmt.getAsObject();
    }
    stmt.free();
    return note;
  },

  updateNote(title, content, id, userId) {
    db.run(
      `UPDATE notes SET title = ?, content = ?, updated_at = datetime('now') WHERE id = ? AND user_id = ?`,
      [title, content, id, userId]
    );
    saveToFile();
  },

  deleteNote(id, userId) {
    db.run('DELETE FROM notes WHERE id = ? AND user_id = ?', [id, userId]);
    saveToFile();
  },
};

module.exports = { initDatabase, queries };
