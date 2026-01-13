const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const config = require('../config/environment');
const { db, generateId } = require('../database/init');

const BCRYPT_ROUNDS = 12;
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_DURATION = 15 * 60 * 1000;

async function hashPassword(password) {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

function generateTokens(userId) {
  const accessToken = jwt.sign(
    { userId, type: 'access' },
    config.jwt.secret,
    { expiresIn: config.jwt.expiresIn }
  );

  const refreshToken = jwt.sign(
    { userId, type: 'refresh', nonce: crypto.randomBytes(16).toString('hex') },
    config.jwt.refreshSecret,
    { expiresIn: config.jwt.refreshExpiresIn }
  );

  return { accessToken, refreshToken };
}

function verifyAccessToken(token) {
  try {
    return jwt.verify(token, config.jwt.secret);
  } catch {
    return null;
  }
}

async function storeRefreshToken(userId, token, userAgent, ipAddress) {
  const tokenId = generateId();
  const decoded = jwt.decode(token);
  const expiresAt = new Date(decoded.exp * 1000);

  const stmt = db.prepare(`
    INSERT INTO refresh_tokens (id, user_id, token, expires_at, user_agent, ip_address)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  stmt.run(tokenId, userId, token, expiresAt.toISOString(), userAgent, ipAddress);
  return tokenId;
}

async function revokeRefreshToken(token) {
  const stmt = db.prepare(`
    UPDATE refresh_tokens
    SET revoked_at = CURRENT_TIMESTAMP
    WHERE token = ? AND revoked_at IS NULL
  `);
  const result = stmt.run(token);
  return result.changes > 0;
}

async function isTokenValid(token) {
  const stmt = db.prepare(`
    SELECT id FROM refresh_tokens
    WHERE token = ? AND revoked_at IS NULL AND expires_at > datetime('now')
  `);
  return stmt.get(token) !== undefined;
}

async function cleanupExpiredTokens() {
  const stmt = db.prepare(`
    DELETE FROM refresh_tokens
    WHERE expires_at < datetime('now') OR revoked_at IS NOT NULL
  `);
  stmt.run();
}

async function registerUser(username, email, password) {
  const userId = generateId();
  const passwordHash = await hashPassword(password);

  const stmt = db.prepare(`
    INSERT INTO users (id, username, email, password_hash)
    VALUES (?, ?, ?, ?)
  `);

  try {
    stmt.run(userId, username, email, passwordHash);
    return { id: userId, username, email };
  } catch (error) {
    if (error.message.includes('UNIQUE constraint failed')) {
      if (error.message.includes('username')) {
        throw new Error('Username already exists');
      }
      if (error.message.includes('email')) {
        throw new Error('Email already exists');
      }
    }
    throw error;
  }
}

async function authenticateUser(username, password) {
  const stmt = db.prepare(`
    SELECT id, username, email, password_hash, failed_attempts, locked_until
    FROM users WHERE username = ? OR email = ?
  `);
  const user = stmt.get(username, username);

  if (!user) {
    return null;
  }

  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    throw new Error('Account temporarily locked due to too many failed attempts');
  }

  const isValid = await verifyPassword(password, user.password_hash);

  if (!isValid) {
    const newFailedAttempts = (user.failed_attempts || 0) + 1;
    let lockedUntil = null;

    if (newFailedAttempts >= MAX_FAILED_ATTEMPTS) {
      lockedUntil = new Date(Date.now() + LOCK_DURATION).toISOString();
    }

    const updateStmt = db.prepare(`
      UPDATE users SET failed_attempts = ?, locked_until = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `);
    updateStmt.run(newFailedAttempts, lockedUntil, user.id);

    if (lockedUntil) {
      throw new Error('Account temporarily locked due to too many failed attempts');
    }

    return null;
  }

  const updateStmt = db.prepare(`
    UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `);
  updateStmt.run(user.id);

  return { id: user.id, username: user.username, email: user.email };
}

function getUserById(userId) {
  const stmt = db.prepare(`
    SELECT id, username, email, created_at, last_login
    FROM users WHERE id = ?
  `);
  return stmt.get(userId);
}

module.exports = {
  hashPassword,
  verifyPassword,
  generateTokens,
  verifyAccessToken,
  storeRefreshToken,
  revokeRefreshToken,
  isTokenValid,
  cleanupExpiredTokens,
  registerUser,
  authenticateUser,
  getUserById
};
