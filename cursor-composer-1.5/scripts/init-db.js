#!/usr/bin/env node
/**
 * Initialize database schema - run once before first start
 */
import initSqlJs from 'sql.js';
import { mkdirSync, existsSync, writeFileSync, readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const dbPath = process.env.DATABASE_PATH || join(__dirname, '..', 'data', 'notes.db');

const dbDir = dirname(dbPath);
if (!existsSync(dbDir)) {
  mkdirSync(dbDir, { recursive: true });
}

const SQL = await initSqlJs();
const db = existsSync(dbPath)
  ? new SQL.Database(readFileSync(dbPath))
  : new SQL.Database();

db.run('PRAGMA journal_mode = WAL');

db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )
`);

db.run(`
  CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)
`);

db.run(`
  CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`);

db.run(`
  CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id)
`);

const data = db.export();
writeFileSync(dbPath, Buffer.from(data));
db.close();

console.log('Database initialized at', dbPath);
