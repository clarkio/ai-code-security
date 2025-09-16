const databaseConnection = require('../database/connection');
const logger = require('../utils/logger');

class AuditLog {
  constructor(data = {}) {
    this.id = data.id;
    this.userId = data.user_id;
    this.action = data.action;
    this.resource = data.resource;
    this.resourceId = data.resource_id;
    this.ipAddress = data.ip_address;
    this.userAgent = data.user_agent;
    this.success = data.success;
    this.errorMessage = data.error_message;
    this.additionalData = data.additional_data;
    this.timestamp = data.timestamp;
  }

  /**
   * Create a new audit log entry
   */
  static async create(auditData) {
    try {
      const {
        userId,
        action,
        resource,
        resourceId,
        ipAddress,
        userAgent,
        success = true,
        errorMessage,
        additionalData
      } = auditData;

      // Validate required fields
      AuditLog.validateAuditData({ action, resource, success });

      // Sanitize user agent to prevent log injection
      const sanitizedUserAgent = AuditLog.sanitizeUserAgent(userAgent);

      // Sanitize additional data to remove sensitive information
      const sanitizedAdditionalData = AuditLog.sanitizeAdditionalData(additionalData);

      const query = `
        INSERT INTO audit_logs (
          user_id, action, resource, resource_id, ip_address, 
          user_agent, success, error_message, additional_data, timestamp
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
        RETURNING id, user_id, action, resource, resource_id, ip_address,
                  user_agent, success, error_message, additional_data, timestamp
      `;

      const result = await databaseConnection.query(query, [
        userId || null,
        action,
        resource,
        resourceId || null,
        ipAddress || null,
        sanitizedUserAgent,
        success,
        errorMessage || null,
        sanitizedAdditionalData ? JSON.stringify(sanitizedAdditionalData) : null
      ]);

      return new AuditLog(result.rows[0]);

    } catch (error) {
      // Don't log audit log creation failures to prevent infinite loops
      console.error('Failed to create audit log:', error.message);
      throw error;
    }
  }

  /**
   * Find audit logs by user ID with pagination
   */
  static async findByUserId(userId, options = {}) {
    try {
      const { 
        limit = 100, 
        offset = 0, 
        action, 
        resource, 
        success,
        startDate,
        endDate 
      } = options;

      let query = `
        SELECT id, user_id, action, resource, resource_id, ip_address,
               user_agent, success, error_message, additional_data, timestamp
        FROM audit_logs 
        WHERE user_id = $1
      `;

      const params = [userId];
      let paramIndex = 2;

      // Add optional filters
      if (action) {
        query += ` AND action = $${paramIndex++}`;
        params.push(action);
      }

      if (resource) {
        query += ` AND resource = $${paramIndex++}`;
        params.push(resource);
      }

      if (success !== undefined) {
        query += ` AND success = $${paramIndex++}`;
        params.push(success);
      }

      if (startDate) {
        query += ` AND timestamp >= $${paramIndex++}`;
        params.push(startDate);
      }

      if (endDate) {
        query += ` AND timestamp <= $${paramIndex++}`;
        params.push(endDate);
      }

      query += ` ORDER BY timestamp DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
      params.push(limit, offset);

      const result = await databaseConnection.query(query, params);

      return result.rows.map(row => new AuditLog(row));

    } catch (error) {
      logger.error('Failed to find audit logs by user ID', {
        error: error.message,
        userId
      });
      throw error;
    }
  }

  /**
   * Find audit logs by action with pagination
   */
  static async findByAction(action, options = {}) {
    try {
      const { 
        limit = 100, 
        offset = 0, 
        success,
        startDate,
        endDate 
      } = options;

      let query = `
        SELECT id, user_id, action, resource, resource_id, ip_address,
               user_agent, success, error_message, additional_data, timestamp
        FROM audit_logs 
        WHERE action = $1
      `;

      const params = [action];
      let paramIndex = 2;

      // Add optional filters
      if (success !== undefined) {
        query += ` AND success = $${paramIndex++}`;
        params.push(success);
      }

      if (startDate) {
        query += ` AND timestamp >= $${paramIndex++}`;
        params.push(startDate);
      }

      if (endDate) {
        query += ` AND timestamp <= $${paramIndex++}`;
        params.push(endDate);
      }

      query += ` ORDER BY timestamp DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
      params.push(limit, offset);

      const result = await databaseConnection.query(query, params);

      return result.rows.map(row => new AuditLog(row));

    } catch (error) {
      logger.error('Failed to find audit logs by action', {
        error: error.message,
        action
      });
      throw error;
    }
  }

  /**
   * Find security-related audit logs (failed logins, violations, etc.)
   */
  static async findSecurityEvents(options = {}) {
    try {
      const { 
        limit = 100, 
        offset = 0, 
        startDate,
        endDate,
        ipAddress 
      } = options;

      const securityActions = [
        'login_failed',
        'account_locked',
        'unauthorized_access',
        'security_violation',
        'rate_limit_exceeded',
        'invalid_token',
        'session_hijack_attempt'
      ];

      let query = `
        SELECT id, user_id, action, resource, resource_id, ip_address,
               user_agent, success, error_message, additional_data, timestamp
        FROM audit_logs 
        WHERE action = ANY($1) OR success = false
      `;

      const params = [securityActions];
      let paramIndex = 2;

      // Add optional filters
      if (startDate) {
        query += ` AND timestamp >= $${paramIndex++}`;
        params.push(startDate);
      }

      if (endDate) {
        query += ` AND timestamp <= $${paramIndex++}`;
        params.push(endDate);
      }

      if (ipAddress) {
        query += ` AND ip_address = $${paramIndex++}`;
        params.push(ipAddress);
      }

      query += ` ORDER BY timestamp DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
      params.push(limit, offset);

      const result = await databaseConnection.query(query, params);

      return result.rows.map(row => new AuditLog(row));

    } catch (error) {
      logger.error('Failed to find security events', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Get audit log statistics
   */
  static async getStatistics(options = {}) {
    try {
      const { 
        userId,
        startDate = new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
        endDate = new Date()
      } = options;

      let baseQuery = `
        FROM audit_logs 
        WHERE timestamp >= $1 AND timestamp <= $2
      `;

      const params = [startDate, endDate];
      let paramIndex = 3;

      if (userId) {
        baseQuery += ` AND user_id = $${paramIndex++}`;
        params.push(userId);
      }

      // Get overall statistics
      const statsQuery = `
        SELECT 
          COUNT(*) as total_events,
          COUNT(CASE WHEN success = true THEN 1 END) as successful_events,
          COUNT(CASE WHEN success = false THEN 1 END) as failed_events,
          COUNT(DISTINCT user_id) as unique_users,
          COUNT(DISTINCT ip_address) as unique_ips
        ${baseQuery}
      `;

      const statsResult = await databaseConnection.query(statsQuery, params);

      // Get action breakdown
      const actionQuery = `
        SELECT action, COUNT(*) as count
        ${baseQuery}
        GROUP BY action
        ORDER BY count DESC
        LIMIT 10
      `;

      const actionResult = await databaseConnection.query(actionQuery, params);

      // Get resource breakdown
      const resourceQuery = `
        SELECT resource, COUNT(*) as count
        ${baseQuery}
        GROUP BY resource
        ORDER BY count DESC
        LIMIT 10
      `;

      const resourceResult = await databaseConnection.query(resourceQuery, params);

      return {
        period: { startDate, endDate },
        overall: statsResult.rows[0],
        actionBreakdown: actionResult.rows,
        resourceBreakdown: resourceResult.rows
      };

    } catch (error) {
      logger.error('Failed to get audit log statistics', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Clean up old audit logs
   */
  static async cleanup(retentionDays = 90) {
    try {
      const cutoffDate = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);

      const query = `
        DELETE FROM audit_logs 
        WHERE timestamp < $1
      `;

      const result = await databaseConnection.query(query, [cutoffDate]);

      logger.info('Audit log cleanup completed', {
        deletedRecords: result.rowCount,
        cutoffDate,
        retentionDays
      });

      return result.rowCount;

    } catch (error) {
      logger.error('Failed to cleanup audit logs', {
        error: error.message,
        retentionDays
      });
      throw error;
    }
  }

  /**
   * Export audit logs for compliance
   */
  static async exportLogs(options = {}) {
    try {
      const {
        userId,
        startDate,
        endDate,
        format = 'json'
      } = options;

      const logs = await AuditLog.findByUserId(userId, {
        limit: 10000, // Large limit for export
        startDate,
        endDate
      });

      if (format === 'csv') {
        return AuditLog.convertToCSV(logs);
      }

      return logs.map(log => log.toJSON());

    } catch (error) {
      logger.error('Failed to export audit logs', {
        error: error.message,
        userId
      });
      throw error;
    }
  }

  /**
   * Convert audit logs to CSV format
   */
  static convertToCSV(logs) {
    if (logs.length === 0) {
      return '';
    }

    const headers = [
      'timestamp', 'userId', 'action', 'resource', 'resourceId',
      'ipAddress', 'success', 'errorMessage'
    ];

    const csvRows = [headers.join(',')];

    logs.forEach(log => {
      const row = [
        log.timestamp,
        log.userId || '',
        log.action,
        log.resource,
        log.resourceId || '',
        log.ipAddress || '',
        log.success,
        (log.errorMessage || '').replace(/,/g, ';') // Replace commas to avoid CSV issues
      ];
      csvRows.push(row.join(','));
    });

    return csvRows.join('\n');
  }

  /**
   * Get audit log data for JSON serialization
   */
  toJSON() {
    return {
      id: this.id,
      userId: this.userId,
      action: this.action,
      resource: this.resource,
      resourceId: this.resourceId,
      ipAddress: this.ipAddress,
      userAgent: this.userAgent,
      success: this.success,
      errorMessage: this.errorMessage,
      additionalData: this.additionalData,
      timestamp: this.timestamp
    };
  }

  // Static utility methods

  /**
   * Validate audit data
   */
  static validateAuditData(auditData) {
    const { action, resource, success } = auditData;

    if (!action || typeof action !== 'string' || action.trim().length === 0) {
      throw new Error('Action is required and must be a non-empty string');
    }

    if (action.length > 50) {
      throw new Error('Action cannot exceed 50 characters');
    }

    if (!resource || typeof resource !== 'string' || resource.trim().length === 0) {
      throw new Error('Resource is required and must be a non-empty string');
    }

    if (resource.length > 50) {
      throw new Error('Resource cannot exceed 50 characters');
    }

    if (typeof success !== 'boolean') {
      throw new Error('Success must be a boolean value');
    }
  }

  /**
   * Sanitize user agent string to prevent log injection
   */
  static sanitizeUserAgent(userAgent) {
    if (!userAgent || typeof userAgent !== 'string') {
      return null;
    }

    // Remove potential log injection characters and limit length
    return userAgent
      .replace(/[\r\n\t]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .substring(0, 1000);
  }

  /**
   * Sanitize additional data to remove sensitive information
   */
  static sanitizeAdditionalData(data) {
    if (!data || typeof data !== 'object') {
      return null;
    }

    const sensitiveFields = [
      'password', 'token', 'secret', 'key', 'authorization',
      'cookie', 'session', 'jwt', 'refresh_token', 'access_token',
      'credit_card', 'ssn', 'social_security'
    ];

    const sanitized = { ...data };

    function sanitizeObject(obj) {
      if (typeof obj !== 'object' || obj === null) {
        return obj;
      }

      const result = Array.isArray(obj) ? [] : {};

      for (const [key, value] of Object.entries(obj)) {
        const lowerKey = key.toLowerCase();

        if (sensitiveFields.some(field => lowerKey.includes(field))) {
          result[key] = '[REDACTED]';
        } else if (typeof value === 'object' && value !== null) {
          result[key] = sanitizeObject(value);
        } else {
          result[key] = value;
        }
      }

      return result;
    }

    return sanitizeObject(sanitized);
  }
}

module.exports = AuditLog;