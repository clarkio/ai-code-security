'use strict';

const crypto = require('crypto');
// bcryptjs: pure-JS implementation of the bcrypt algorithm (no native build).
// API-compatible with the native `bcrypt` package for the calls used here.
const bcrypt = require('bcryptjs');
const db = require('../db');
const config = require('../config');

// A valid bcrypt hash of a random throwaway value, computed once at startup.
// Used as a timing decoy so that login attempts for non-existent usernames take
// the same amount of work as real ones (prevents username enumeration via timing).
const DECOY_HASH = bcrypt.hashSync(
  crypto.randomBytes(32).toString('hex'),
  config.bcryptRounds
);

// Prepared statements are compiled once and reused. User input is always bound
// as parameters (?), so SQL injection is structurally impossible here.
const insertUser = db.prepare(
  'INSERT INTO users (username, password_hash) VALUES (?, ?)'
);
const selectByUsername = db.prepare(
  'SELECT id, username, password_hash FROM users WHERE username = ?'
);
const selectById = db.prepare('SELECT id, username FROM users WHERE id = ?');

/**
 * Create a user with a securely hashed password.
 * @returns {{id:number, username:string}}
 * @throws if the username is already taken (UNIQUE constraint).
 */
async function createUser(username, password) {
  const passwordHash = await bcrypt.hash(password, config.bcryptRounds);
  const info = insertUser.run(username, passwordHash);
  return { id: info.lastInsertRowid, username };
}

/**
 * Verify credentials in constant-ish time.
 *
 * To avoid leaking whether a username exists via timing, we always run a bcrypt
 * comparison even when the user is not found (against a dummy hash).
 * @returns {{id:number, username:string} | null}
 */
async function verifyCredentials(username, password) {
  const row = selectByUsername.get(username);
  const hash = row ? row.password_hash : DECOY_HASH;

  const ok = await bcrypt.compare(password, hash);
  if (!row || !ok) return null;
  return { id: row.id, username: row.username };
}

function findById(id) {
  return selectById.get(id) || null;
}

function usernameExists(username) {
  return Boolean(selectByUsername.get(username));
}

module.exports = { createUser, verifyCredentials, findById, usernameExists };
