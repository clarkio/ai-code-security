// Test environment setup
process.env.NODE_ENV = 'test';

// Set test-specific environment variables
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test_db';
process.env.REDIS_URL = 'redis://localhost:6379/1';
process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing-only';
process.env.JWT_REFRESH_SECRET = 'test-jwt-refresh-secret-key-for-testing-only';
// Generate a proper 256-bit (32 byte) encryption key for testing
const crypto = require('crypto');
process.env.ENCRYPTION_KEY = crypto.randomBytes(32).toString('base64');
process.env.CORS_ORIGIN = 'http://localhost:3000';

// Increase timeout for security operations
jest.setTimeout(10000);

// Mock console methods in tests to reduce noise
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};
