"use strict";

/**
 * Database layer using better-sqlite3.
 *
 * Security notes:
 *  - All queries use parameterized statements (prevents SQL injection).
 *  - The DB file lives outside the web root (./data/).
 *  - Foreign keys & WAL mode enabled for integrity & concurrency.
 *  - Passwords are NEVER stored — we store bcrypt hashes only.
 */

const path = require("path");
const fs = require("fs");
const { DatabaseSync } = require("node:sqlite");

const config = require("../config/env");

let db = null;

function getDb() {
  if (db) return db;

  // Ensure the data directory exists
  const dbDir = path.dirname(config.dbPath);
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }

  db = new DatabaseSync(config.dbPath);

  // Hardening (node:sqlite uses exec() for pragmas — no .pragma() method)
  db.exec("PRAGMA journal_mode = WAL");
  db.exec("PRAGMA foreign_keys = ON");
  db.exec("PRAGMA synchronous = NORMAL"); // safe with WAL

  migrate(db);
  return db;
}

function migrate(database) {
  // Users table
  database.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at    TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // Notes table — each note belongs to exactly one user (ownership enforced in queries)
  database.exec(`
    CREATE TABLE IF NOT EXISTS notes (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL,
      title      TEXT NOT NULL,
      body       TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  // Index for fast lookup of a user's notes
  database.exec(`
    CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id);
  `);
}

function closeDb() {
  if (db) {
    db.close();
    db = null;
  }
}

module.exports = { getDb, closeDb };
