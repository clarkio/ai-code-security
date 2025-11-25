/**
 * Audit Log Model
 * Records security-relevant events for monitoring and compliance
 */

const { v4: uuidv4 } = require("uuid");
const db = require("../database");

// Actions that should be logged
const AUDIT_ACTIONS = {
  LOGIN_SUCCESS: "LOGIN_SUCCESS",
  LOGIN_FAILED: "LOGIN_FAILED",
  LOGOUT: "LOGOUT",
  REGISTER: "REGISTER",
  PASSWORD_CHANGE: "PASSWORD_CHANGE",
  TOKEN_REFRESH: "TOKEN_REFRESH",
  NOTE_CREATE: "NOTE_CREATE",
  NOTE_UPDATE: "NOTE_UPDATE",
  NOTE_DELETE: "NOTE_DELETE",
  ACCOUNT_LOCKED: "ACCOUNT_LOCKED",
  UNAUTHORIZED_ACCESS: "UNAUTHORIZED_ACCESS",
  RATE_LIMIT_EXCEEDED: "RATE_LIMIT_EXCEEDED",
};

class AuditLog {
  /**
   * Create an audit log entry
   */
  static log(
    action,
    {
      userId = null,
      resource = null,
      resourceId = null,
      ipAddress = null,
      userAgent = null,
      details = null,
    } = {}
  ) {
    const id = uuidv4();

    // Sanitize and truncate details to prevent log bloat
    let sanitizedDetails = null;
    if (details) {
      // Remove sensitive fields
      const safeDetails = { ...details };
      delete safeDetails.password;
      delete safeDetails.token;
      delete safeDetails.secret;

      sanitizedDetails = JSON.stringify(safeDetails).substring(0, 1000);
    }

    // Truncate user agent
    const safeUserAgent = userAgent ? userAgent.substring(0, 500) : null;

    const stmt = db.prepare(`
      INSERT INTO audit_log (id, user_id, action, resource, resource_id, ip_address, user_agent, details)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      userId,
      action,
      resource,
      resourceId,
      ipAddress,
      safeUserAgent,
      sanitizedDetails
    );

    return id;
  }

  /**
   * Get audit logs for a user
   */
  static getByUserId(userId, { limit = 50, offset = 0 } = {}) {
    const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 100);
    const safeOffset = Math.max(parseInt(offset, 10) || 0, 0);

    const stmt = db.prepare(`
      SELECT id, user_id, action, resource, resource_id, ip_address, created_at
      FROM audit_log
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `);

    return stmt.all(userId, safeLimit, safeOffset);
  }

  /**
   * Get recent security events (for admin monitoring)
   */
  static getSecurityEvents({ limit = 100, actions = null } = {}) {
    const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 100, 1), 1000);

    let query = `
      SELECT id, user_id, action, resource, resource_id, ip_address, created_at
      FROM audit_log
    `;

    const params = [];

    if (actions && actions.length > 0) {
      // Whitelist actions to prevent injection
      const safeActions = actions.filter((a) =>
        Object.values(AUDIT_ACTIONS).includes(a)
      );
      if (safeActions.length > 0) {
        const placeholders = safeActions.map(() => "?").join(", ");
        query += ` WHERE action IN (${placeholders})`;
        params.push(...safeActions);
      }
    }

    query += ` ORDER BY created_at DESC LIMIT ?`;
    params.push(safeLimit);

    const stmt = db.prepare(query);
    return stmt.all(...params);
  }
}

module.exports = { AuditLog, AUDIT_ACTIONS };
