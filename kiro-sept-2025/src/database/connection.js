const { Pool } = require('pg');
const config = require('../config/environment');
const logger = require('../utils/logger');

class DatabaseConnection {
  constructor() {
    this.pool = null;
    this.isConnected = false;
    this.retryAttempts = 0;
    this.maxRetries = 5;
    this.retryDelay = 1000; // Start with 1 second
  }

  /**
   * Initialize database connection pool with SSL encryption
   */
  async initialize() {
    try {
      // Parse DATABASE_URL and configure SSL
      const connectionConfig = {
        connectionString: config.database.url,
        ssl: config.database.ssl ? {
          rejectUnauthorized: false, // For development - should be true in production
          sslmode: 'require'
        } : false,
        // Connection pool configuration
        max: 20, // Maximum number of clients in the pool
        min: 5,  // Minimum number of clients in the pool
        idleTimeoutMillis: 30000, // Close idle clients after 30 seconds
        connectionTimeoutMillis: 10000, // Return error after 10 seconds if connection could not be established
        maxUses: 7500, // Close (and replace) a connection after it has been used this many times
        allowExitOnIdle: false, // Don't allow the pool to exit on idle
      };

      this.pool = new Pool(connectionConfig);

      // Set up event handlers
      this.setupEventHandlers();

      // Test the connection
      await this.testConnection();
      
      this.isConnected = true;
      this.retryAttempts = 0;
      
      logger.info('Database connection pool initialized successfully', {
        ssl: config.database.ssl,
        maxConnections: connectionConfig.max,
        minConnections: connectionConfig.min
      });

    } catch (error) {
      logger.error('Failed to initialize database connection', {
        error: error.message,
        retryAttempts: this.retryAttempts
      });
      
      await this.handleConnectionError(error);
    }
  }

  /**
   * Set up event handlers for the connection pool
   */
  setupEventHandlers() {
    // Handle connection errors
    this.pool.on('error', async (error) => {
      logger.error('Database pool error', {
        error: error.message,
        code: error.code
      });
      
      this.isConnected = false;
      await this.handleConnectionError(error);
    });

    // Handle new client connections
    this.pool.on('connect', (client) => {
      logger.debug('New database client connected', {
        processID: client.processID,
        secretKey: client.secretKey ? '[REDACTED]' : 'none'
      });
    });

    // Handle client acquisition
    this.pool.on('acquire', (client) => {
      logger.debug('Database client acquired from pool', {
        processID: client.processID
      });
    });

    // Handle client removal
    this.pool.on('remove', (client) => {
      logger.debug('Database client removed from pool', {
        processID: client.processID
      });
    });
  }

  /**
   * Test database connection
   */
  async testConnection() {
    const client = await this.pool.connect();
    try {
      // Test query to verify connection and SSL
      const result = await client.query('SELECT version(), current_setting(\'ssl\') as ssl_status');
      
      logger.info('Database connection test successful', {
        version: result.rows[0].version.split(' ')[0] + ' ' + result.rows[0].version.split(' ')[1],
        ssl: result.rows[0].ssl_status,
        timestamp: new Date().toISOString()
      });
      
      return result.rows[0];
    } finally {
      client.release();
    }
  }

  /**
   * Handle connection errors with retry logic
   */
  async handleConnectionError(error) {
    if (this.retryAttempts < this.maxRetries) {
      this.retryAttempts++;
      const delay = this.retryDelay * Math.pow(2, this.retryAttempts - 1); // Exponential backoff
      
      logger.warn(`Database connection failed, retrying in ${delay}ms`, {
        attempt: this.retryAttempts,
        maxRetries: this.maxRetries,
        error: error.message
      });
      
      setTimeout(() => {
        this.initialize();
      }, delay);
    } else {
      logger.error('Database connection failed after maximum retry attempts', {
        maxRetries: this.maxRetries,
        error: error.message
      });
      
      // In production, you might want to exit the process or trigger alerts
      if (config.app.env === 'production') {
        process.exit(1);
      }
    }
  }

  /**
   * Get a client from the pool
   */
  async getClient() {
    if (!this.isConnected || !this.pool) {
      throw new Error('Database not connected. Call initialize() first.');
    }
    
    try {
      return await this.pool.connect();
    } catch (error) {
      logger.error('Failed to get database client', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Execute a query with automatic client management
   */
  async query(text, params = []) {
    if (!this.isConnected || !this.pool) {
      throw new Error('Database not connected. Call initialize() first.');
    }

    const start = Date.now();
    const client = await this.getClient();
    
    try {
      const result = await client.query(text, params);
      const duration = Date.now() - start;
      
      logger.debug('Database query executed', {
        duration: `${duration}ms`,
        rows: result.rowCount,
        command: result.command
      });
      
      return result;
    } catch (error) {
      logger.error('Database query failed', {
        error: error.message,
        query: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
        duration: `${Date.now() - start}ms`
      });
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Execute a transaction
   */
  async transaction(callback) {
    if (!this.isConnected || !this.pool) {
      throw new Error('Database not connected. Call initialize() first.');
    }

    const client = await this.getClient();
    
    try {
      await client.query('BEGIN');
      
      const result = await callback(client);
      
      await client.query('COMMIT');
      
      logger.debug('Database transaction completed successfully');
      
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      
      logger.error('Database transaction rolled back', {
        error: error.message
      });
      
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Check if database is healthy
   */
  async healthCheck() {
    try {
      if (!this.isConnected || !this.pool) {
        return { healthy: false, error: 'Database not connected' };
      }

      const result = await this.query('SELECT 1 as health_check');
      
      return {
        healthy: true,
        totalConnections: this.pool.totalCount,
        idleConnections: this.pool.idleCount,
        waitingConnections: this.pool.waitingCount,
        ssl: config.database.ssl
      };
    } catch (error) {
      return {
        healthy: false,
        error: error.message
      };
    }
  }

  /**
   * Gracefully close all connections
   */
  async close() {
    if (this.pool) {
      logger.info('Closing database connection pool');
      
      try {
        await this.pool.end();
        this.isConnected = false;
        this.pool = null;
        
        logger.info('Database connection pool closed successfully');
      } catch (error) {
        logger.error('Error closing database connection pool', {
          error: error.message
        });
        throw error;
      }
    }
  }
}

// Create singleton instance
const databaseConnection = new DatabaseConnection();

module.exports = databaseConnection;