/**
 * Refresh Token Model
 * Secure storage of refresh tokens with hashing
 */

const { v4: uuidv4 } = require("uuid");
const crypto = require("crypto");
const db = require("../database");
const logger = require("../config/logger");

class RefreshToken {
  /**
   * Hash a token for secure storage
   */
  static hashToken(token) {
    return crypto.createHash("sha256").update(token).digest("hex");
  }

  /**
   * Create a new refresh token
   */
  static create(userId, expiresInDays = 7) {
    const id = uuidv4();
    const token = crypto.randomBytes(64).toString("hex");
    const tokenHash = this.hashToken(token);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + expiresInDays);

    const stmt = db.prepare(`
      INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at)
      VALUES (?, ?, ?, ?)
    `);

    stmt.run(id, userId, tokenHash, expiresAt.toISOString());

    logger.info(`Refresh token created for user: ${userId}`);

    // Return the plain token (only time it's available)
    return {
      id,
      token,
      expiresAt: expiresAt.toISOString(),
    };
  }

  /**
   * Verify and get refresh token
   */
  static verify(token) {
    const tokenHash = this.hashToken(token);

    const stmt = db.prepare(`
      SELECT rt.*, u.id as user_id, u.username, u.email
      FROM refresh_tokens rt
      JOIN users u ON rt.user_id = u.id
      WHERE rt.token_hash = ?
        AND rt.revoked = 0
        AND datetime(rt.expires_at) > datetime('now')
    `);

    return stmt.get(tokenHash);
  }

  /**
   * Revoke a specific refresh token
   */
  static revoke(token) {
    const tokenHash = this.hashToken(token);

    const stmt = db.prepare(`
      UPDATE refresh_tokens
      SET revoked = 1
      WHERE token_hash = ?
    `);

    const result = stmt.run(tokenHash);

    if (result.changes > 0) {
      logger.info("Refresh token revoked");
    }

    return result.changes > 0;
  }

  /**
   * Revoke all refresh tokens for a user (logout from all devices)
   */
  static revokeAllForUser(userId) {
    const stmt = db.prepare(`
      UPDATE refresh_tokens
      SET revoked = 1
      WHERE user_id = ?
    `);

    const result = stmt.run(userId);

    logger.info(`All refresh tokens revoked for user: ${userId}`);

    return result.changes;
  }

  /**
   * Delete expired and revoked tokens (cleanup)
   */
  static cleanup() {
    const stmt = db.prepare(`
      DELETE FROM refresh_tokens
      WHERE datetime(expires_at) < datetime('now')
        OR revoked = 1
    `);

    const result = stmt.run();

    if (result.changes > 0) {
      logger.info(`Cleaned up ${result.changes} expired/revoked tokens`);
    }

    return result.changes;
  }
}

module.exports = RefreshToken;
