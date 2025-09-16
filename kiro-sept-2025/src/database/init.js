const databaseConnection = require('./connection');
const logger = require('../utils/logger');

class DatabaseInitializer {
  constructor() {
    this.db = databaseConnection;
  }

  /**
   * Initialize database with proper permissions and security settings
   */
  async initialize() {
    try {
      logger.info('Starting database initialization');

      // Ensure database connection is established
      if (!this.db.isConnected) {
        await this.db.initialize();
      }

      // Create extensions if they don't exist
      await this.createExtensions();

      // Create tables with proper constraints and indexes
      await this.createTables();

      // Set up database security settings
      await this.setupSecurity();

      // Create indexes for performance and security
      await this.createIndexes();

      logger.info('Database initialization completed successfully');

    } catch (error) {
      logger.error('Database initialization failed', {
        error: error.message,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Create necessary PostgreSQL extensions
   */
  async createExtensions() {
    try {
      // UUID extension for generating UUIDs
      await this.db.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
      
      // pgcrypto for additional cryptographic functions
      await this.db.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto"');
      
      logger.info('Database extensions created successfully');
    } catch (error) {
      logger.error('Failed to create database extensions', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Create all required tables with security constraints
   */
  async createTables() {
    await this.db.transaction(async (client) => {
      // Create users table
      await client.query(`
        CREATE TABLE IF NOT EXISTS users (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          email_encrypted TEXT NOT NULL UNIQUE,
          email_hash TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          is_active BOOLEAN DEFAULT true,
          failed_login_attempts INTEGER DEFAULT 0,
          last_failed_login TIMESTAMP WITH TIME ZONE,
          account_locked_until TIMESTAMP WITH TIME ZONE,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          last_login_at TIMESTAMP WITH TIME ZONE,
          
          -- Security constraints
          CONSTRAINT users_email_encrypted_not_empty CHECK (length(email_encrypted) > 0),
          CONSTRAINT users_email_hash_not_empty CHECK (length(email_hash) > 0),
          CONSTRAINT users_password_hash_not_empty CHECK (length(password_hash) > 0),
          CONSTRAINT users_failed_attempts_non_negative CHECK (failed_login_attempts >= 0),
          CONSTRAINT users_failed_attempts_reasonable CHECK (failed_login_attempts <= 100)
        )
      `);

      // Create notes table
      await client.query(`
        CREATE TABLE IF NOT EXISTS notes (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          title_encrypted TEXT NOT NULL,
          content_encrypted TEXT NOT NULL,
          encryption_iv TEXT NOT NULL,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          is_deleted BOOLEAN DEFAULT false,
          
          -- Security constraints
          CONSTRAINT notes_title_encrypted_not_empty CHECK (length(title_encrypted) > 0),
          CONSTRAINT notes_content_encrypted_not_empty CHECK (length(content_encrypted) > 0),
          CONSTRAINT notes_encryption_iv_not_empty CHECK (length(encryption_iv) > 0),
          CONSTRAINT notes_content_length_limit CHECK (length(content_encrypted) <= 50000) -- Encrypted content size limit
        )
      `);

      // Create audit_logs table
      await client.query(`
        CREATE TABLE IF NOT EXISTS audit_logs (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          user_id UUID REFERENCES users(id) ON DELETE SET NULL,
          action VARCHAR(50) NOT NULL,
          resource VARCHAR(50) NOT NULL,
          resource_id UUID,
          ip_address INET,
          user_agent TEXT,
          success BOOLEAN NOT NULL,
          error_message TEXT,
          additional_data JSONB,
          timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          
          -- Security constraints
          CONSTRAINT audit_logs_action_not_empty CHECK (length(action) > 0),
          CONSTRAINT audit_logs_resource_not_empty CHECK (length(resource) > 0),
          CONSTRAINT audit_logs_user_agent_length CHECK (length(user_agent) <= 1000)
        )
      `);

      // Create sessions table for Redis backup/audit
      await client.query(`
        CREATE TABLE IF NOT EXISTS sessions (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          session_id VARCHAR(255) NOT NULL UNIQUE,
          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          token_id UUID NOT NULL,
          ip_address INET,
          user_agent TEXT,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
          is_active BOOLEAN DEFAULT true,
          last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          
          -- Security constraints
          CONSTRAINT sessions_session_id_not_empty CHECK (length(session_id) > 0),
          CONSTRAINT sessions_expires_at_future CHECK (expires_at > created_at),
          CONSTRAINT sessions_user_agent_length CHECK (length(user_agent) <= 1000)
        )
      `);

      logger.info('Database tables created successfully');
    });
  }

  /**
   * Set up database security settings
   */
  async setupSecurity() {
    try {
      // Set row level security policies (if supported)
      await this.db.query('ALTER TABLE notes ENABLE ROW LEVEL SECURITY');
      
      // Create policy for notes - users can only access their own notes
      await this.db.query(`
        CREATE POLICY IF NOT EXISTS notes_user_policy ON notes
        FOR ALL TO current_user
        USING (user_id = current_setting('app.current_user_id')::UUID)
      `);

      // Set up automatic timestamp updates
      await this.createUpdateTimestampTrigger();

      logger.info('Database security settings configured');
    } catch (error) {
      // Row level security might not be available in all PostgreSQL versions
      logger.warn('Some security features could not be enabled', {
        error: error.message
      });
    }
  }

  /**
   * Create trigger for automatic timestamp updates
   */
  async createUpdateTimestampTrigger() {
    await this.db.transaction(async (client) => {
      // Create trigger function
      await client.query(`
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
          NEW.updated_at = CURRENT_TIMESTAMP;
          RETURN NEW;
        END;
        $$ language 'plpgsql'
      `);

      // Create triggers for tables with updated_at columns
      const tablesWithUpdatedAt = ['users', 'notes'];
      
      for (const table of tablesWithUpdatedAt) {
        await client.query(`
          DROP TRIGGER IF EXISTS update_${table}_updated_at ON ${table}
        `);
        
        await client.query(`
          CREATE TRIGGER update_${table}_updated_at
          BEFORE UPDATE ON ${table}
          FOR EACH ROW
          EXECUTE FUNCTION update_updated_at_column()
        `);
      }

      logger.info('Timestamp update triggers created');
    });
  }

  /**
   * Create indexes for performance and security
   */
  async createIndexes() {
    try {
      // Users table indexes
      await this.db.query('CREATE INDEX IF NOT EXISTS idx_users_email_hash ON users(email_hash)');
      await this.db.query('CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active)');
      await this.db.query('CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at)');
      await this.db.query('CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login_at)');

      // Notes table indexes
      await this.db.query('CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id)');
      await this.db.query('CREATE INDEX IF NOT EXISTS idx_notes_user_created ON notes(user_id, created_at DESC)');
      await this.db.query('CREATE INDEX IF NOT EXISTS idx_notes_is_deleted ON notes(is_deleted)');
      await this.db.query('CREATE INDEX IF NOT EXISTS idx_notes_updated_at ON notes(updated_at)');

      // Audit logs indexes
      await this.db.query('CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)');
      await this.db.query('CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC)');
      await this.db.query('CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)');
      await this.db.query('CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource, resource_id)');
      await this.db.query('CREATE INDEX IF NOT EXISTS idx_audit_logs_ip_address ON audit_logs(ip_address)');

      // Sessions table indexes
      await this.db.query('CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id)');
      await this.db.query('CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)');
      await this.db.query('CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)');
      await this.db.query('CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON sessions(is_active)');

      logger.info('Database indexes created successfully');
    } catch (error) {
      logger.error('Failed to create database indexes', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Clean up expired sessions and audit logs
   */
  async cleanup() {
    try {
      const now = new Date();
      
      // Clean up expired sessions
      const expiredSessions = await this.db.query(
        'DELETE FROM sessions WHERE expires_at < $1 OR (is_active = false AND last_activity < $2)',
        [now, new Date(now.getTime() - 24 * 60 * 60 * 1000)] // 24 hours ago
      );

      // Clean up old audit logs (keep last 90 days)
      const oldAuditLogs = await this.db.query(
        'DELETE FROM audit_logs WHERE timestamp < $1',
        [new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000)] // 90 days ago
      );

      logger.info('Database cleanup completed', {
        expiredSessions: expiredSessions.rowCount,
        oldAuditLogs: oldAuditLogs.rowCount
      });

    } catch (error) {
      logger.error('Database cleanup failed', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Verify database integrity and security
   */
  async verify() {
    try {
      const checks = [];

      // Check if all required tables exist
      const tables = await this.db.query(`
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_type = 'BASE TABLE'
      `);

      const requiredTables = ['users', 'notes', 'audit_logs', 'sessions'];
      const existingTables = tables.rows.map(row => row.table_name);
      
      for (const table of requiredTables) {
        checks.push({
          check: `Table ${table} exists`,
          passed: existingTables.includes(table)
        });
      }

      // Check if required indexes exist
      const indexes = await this.db.query(`
        SELECT indexname 
        FROM pg_indexes 
        WHERE schemaname = 'public'
      `);

      const requiredIndexes = [
        'idx_users_email_hash',
        'idx_notes_user_id',
        'idx_audit_logs_timestamp',
        'idx_sessions_session_id'
      ];
      
      const existingIndexes = indexes.rows.map(row => row.indexname);
      
      for (const index of requiredIndexes) {
        checks.push({
          check: `Index ${index} exists`,
          passed: existingIndexes.includes(index)
        });
      }

      // Check SSL connection
      const sslCheck = await this.db.query("SELECT current_setting('ssl') as ssl_status");
      checks.push({
        check: 'SSL connection enabled',
        passed: sslCheck.rows[0].ssl_status === 'on'
      });

      const failedChecks = checks.filter(check => !check.passed);
      
      if (failedChecks.length > 0) {
        logger.error('Database verification failed', {
          failedChecks: failedChecks.map(check => check.check)
        });
        return false;
      }

      logger.info('Database verification passed', {
        totalChecks: checks.length
      });
      
      return true;

    } catch (error) {
      logger.error('Database verification error', {
        error: error.message
      });
      return false;
    }
  }
}

module.exports = new DatabaseInitializer();