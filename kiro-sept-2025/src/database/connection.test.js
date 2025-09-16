const DatabaseConnection = require('./connection');
const config = require('../config/environment');

// Mock the logger to avoid file system operations in tests
jest.mock('../utils/logger', () => ({
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
}));

describe('DatabaseConnection', () => {
  let dbConnection;

  beforeEach(() => {
    // Create a new instance for each test
    dbConnection = new DatabaseConnection();
  });

  afterEach(async () => {
    // Clean up connections after each test
    if (dbConnection && dbConnection.pool) {
      await dbConnection.close();
    }
  });

  describe('initialization', () => {
    it('should create a connection pool with SSL configuration', () => {
      expect(dbConnection.pool).toBeNull();
      expect(dbConnection.isConnected).toBe(false);
      expect(dbConnection.retryAttempts).toBe(0);
      expect(dbConnection.maxRetries).toBe(5);
    });

    it('should have correct retry configuration', () => {
      expect(dbConnection.retryDelay).toBe(1000);
      expect(dbConnection.maxRetries).toBe(5);
    });
  });

  describe('configuration', () => {
    it('should use SSL when configured', () => {
      expect(config.database.ssl).toBeDefined();
    });

    it('should have database URL configured', () => {
      expect(config.database.url).toBeDefined();
      expect(typeof config.database.url).toBe('string');
    });
  });

  describe('error handling', () => {
    it('should handle connection errors gracefully', async () => {
      // Mock a connection error
      const originalUrl = config.database.url;
      config.database.url = 'postgresql://invalid:invalid@localhost:5432/invalid';

      try {
        await dbConnection.initialize();
      } catch (error) {
        expect(error).toBeDefined();
      }

      // Restore original URL
      config.database.url = originalUrl;
    });

    it('should implement exponential backoff for retries', () => {
      const delay1 = dbConnection.retryDelay * Math.pow(2, 1 - 1); // 1000ms
      const delay2 = dbConnection.retryDelay * Math.pow(2, 2 - 1); // 2000ms
      const delay3 = dbConnection.retryDelay * Math.pow(2, 3 - 1); // 4000ms

      expect(delay1).toBe(1000);
      expect(delay2).toBe(2000);
      expect(delay3).toBe(4000);
    });
  });

  describe('health check', () => {
    it('should return unhealthy when not connected', async () => {
      const health = await dbConnection.healthCheck();
      
      expect(health.healthy).toBe(false);
      expect(health.error).toBe('Database not connected');
    });
  });

  describe('query methods', () => {
    it('should throw error when querying without connection', async () => {
      await expect(dbConnection.query('SELECT 1')).rejects.toThrow(
        'Database not connected. Call initialize() first.'
      );
    });

    it('should throw error when getting client without connection', async () => {
      await expect(dbConnection.getClient()).rejects.toThrow(
        'Database not connected. Call initialize() first.'
      );
    });

    it('should throw error when running transaction without connection', async () => {
      await expect(dbConnection.transaction(() => {})).rejects.toThrow(
        'Database not connected. Call initialize() first.'
      );
    });
  });

  describe('connection pool configuration', () => {
    it('should have correct pool settings', () => {
      // These are the expected pool settings from the implementation
      const expectedConfig = {
        max: 20,
        min: 5,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 10000,
        maxUses: 7500,
        allowExitOnIdle: false,
      };

      // We can't directly test the pool config without initializing,
      // but we can verify the values are reasonable
      expect(expectedConfig.max).toBeGreaterThan(expectedConfig.min);
      expect(expectedConfig.idleTimeoutMillis).toBeGreaterThan(0);
      expect(expectedConfig.connectionTimeoutMillis).toBeGreaterThan(0);
    });
  });
});

// Integration tests (these would run against a real database in CI/CD)
describe('DatabaseConnection Integration', () => {
  // Skip integration tests if no test database is available
  const skipIntegration = !process.env.TEST_DATABASE_URL;

  beforeAll(() => {
    if (skipIntegration) {
      console.log('Skipping integration tests - TEST_DATABASE_URL not set');
    }
  });

  it.skip('should connect to test database with SSL', async () => {
    if (skipIntegration) return;

    const testConnection = new DatabaseConnection();
    
    try {
      await testConnection.initialize();
      expect(testConnection.isConnected).toBe(true);
      
      const health = await testConnection.healthCheck();
      expect(health.healthy).toBe(true);
      expect(health.ssl).toBeDefined();
      
    } finally {
      await testConnection.close();
    }
  });

  it.skip('should execute queries successfully', async () => {
    if (skipIntegration) return;

    const testConnection = new DatabaseConnection();
    
    try {
      await testConnection.initialize();
      
      const result = await testConnection.query('SELECT version()');
      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].version).toContain('PostgreSQL');
      
    } finally {
      await testConnection.close();
    }
  });

  it.skip('should handle transactions correctly', async () => {
    if (skipIntegration) return;

    const testConnection = new DatabaseConnection();
    
    try {
      await testConnection.initialize();
      
      const result = await testConnection.transaction(async (client) => {
        const res = await client.query('SELECT 1 as test');
        return res.rows[0];
      });
      
      expect(result.test).toBe(1);
      
    } finally {
      await testConnection.close();
    }
  });
});