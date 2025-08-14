import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import argon2 from 'argon2';

const databaseFile = process.env.DATABASE_FILE || './data/notes.db';
const dbPath = path.resolve(process.cwd(), databaseFile);

const dataDir = path.dirname(dbPath);
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(dbPath, { fileMustExist: false });
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE CHECK(length(username) BETWEEN 3 AND 30),
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 200),
    body TEXT NOT NULL CHECK(length(body) <= 5000),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TRIGGER IF NOT EXISTS notes_updated_at
AFTER UPDATE ON notes
FOR EACH ROW
BEGIN
  UPDATE notes SET updated_at = datetime('now') WHERE id = OLD.id;
END;
`);

// User operations
export function createUser({ username, password }) {
    const passwordHash = argon2.hash(password, { type: argon2.argon2id, memoryCost: 2 ** 16, timeCost: 3, parallelism: 1 });
    return passwordHash.then((hash) => {
        const stmt = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)');
        const info = stmt.run(username, hash);
        return info.lastInsertRowid;
    });
}

export function getUserByUsername(username) {
    const stmt = db.prepare('SELECT id, username, password_hash FROM users WHERE username = ?');
    return stmt.get(username);
}

export function getUserById(id) {
    const stmt = db.prepare('SELECT id, username FROM users WHERE id = ?');
    return stmt.get(id);
}

export async function verifyUserPassword(username, password) {
    const user = getUserByUsername(username);
    if (!user) return null;
    const ok = await argon2.verify(user.password_hash, password, { type: argon2.argon2id });
    if (!ok) return null;
    return { id: user.id, username: user.username };
}

// Note operations
export function listNotesByUser(userId) {
    const stmt = db.prepare('SELECT id, title, body, created_at, updated_at FROM notes WHERE user_id = ? ORDER BY updated_at DESC');
    return stmt.all(userId);
}

export function getNoteByIdAndUser(id, userId) {
    const stmt = db.prepare('SELECT id, title, body, created_at, updated_at FROM notes WHERE id = ? AND user_id = ?');
    return stmt.get(id, userId);
}

export function createNote({ userId, title, body }) {
    const stmt = db.prepare('INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)');
    const info = stmt.run(userId, title, body);
    return info.lastInsertRowid;
}

export function updateNote({ id, userId, title, body }) {
    const stmt = db.prepare('UPDATE notes SET title = ?, body = ? WHERE id = ? AND user_id = ?');
    const info = stmt.run(title, body, id, userId);
    return info.changes > 0;
}

export function deleteNote({ id, userId }) {
    const stmt = db.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?');
    const info = stmt.run(id, userId);
    return info.changes > 0;
}


