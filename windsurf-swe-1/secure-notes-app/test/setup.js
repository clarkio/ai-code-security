const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');

// Configure environment variables for testing
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret';
process.env.JWT_EXPIRES_IN = '90d';
process.env.JWT_COOKIE_EXPIRES_IN = '90';
process.env.RATE_LIMIT_MAX = '1000';
process.env.RATE_LIMIT_WINDOW_MS = '900000';
process.env.MONGODB_URI = 'mongodb://localhost:27017/secure-notes-test';

// Global test setup
let mongoServer;

// Mock console methods to keep test output clean
const originalConsoleLog = console.log;
const originalConsoleError = console.error;
const originalConsoleWarn = console.warn;

beforeAll(async () => {
  // Suppress console output during tests
  console.log = jest.fn();
  console.error = jest.fn();
  console.warn = jest.fn();
  
  // Start in-memory MongoDB server
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  
  // Set the MongoDB URI for testing
  process.env.MONGODB_URI = mongoUri;
  
  // Connect to the in-memory database
  await mongoose.connect(mongoUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
  
  // Store the MongoDB instance in global for teardown
  global.__MONGOD__ = mongoServer;
});

afterAll(async () => {
  // Disconnect from the in-memory database
  await mongoose.disconnect();
  
  // Stop the in-memory MongoDB server
  if (global.__MONGOD__) {
    await global.__MONGOD__.stop();
  }
  
  // Restore original console methods
  console.log = originalConsoleLog;
  console.error = originalConsoleError;
  console.warn = originalConsoleWarn;
});

// Clear all test data after each test
afterEach(async () => {
  const collections = mongoose.connection.collections;
  
  for (const key in collections) {
    const collection = collections[key];
    await collection.deleteMany({});
  }
});
