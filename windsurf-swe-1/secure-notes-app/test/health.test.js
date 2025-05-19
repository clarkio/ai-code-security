const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const { app } = require('../src/server');

let mongoServer;
let server;

beforeAll(async () => {
  // Start an in-memory MongoDB server for testing
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  
  // Connect to the in-memory database
  await mongoose.connect(mongoUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
  
  // Start the server on a random port
  server = app.listen(0); // 0 means random port
});

afterAll(async () => {
  // Close the server and database connection
  await server.close();
  await mongoose.disconnect();
  await mongoServer.stop();
});

describe('Health Check API', () => {
  it('should return 200 and health status', async () => {
    const res = await request(server).get('/api/v1/health');
    
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('status', 'OK');
    expect(res.body).toHaveProperty('database', 'connected');
    expect(res.body).toHaveProperty('timestamp');
    expect(res.body).toHaveProperty('uptime');
    expect(res.body).toHaveProperty('memory');
    expect(res.body.memory).toHaveProperty('rss');
    expect(res.body.memory).toHaveProperty('heapTotal');
    expect(res.body.memory).toHaveProperty('heapUsed');
    expect(res.body).toHaveProperty('nodeVersion');
    expect(res.body).toHaveProperty('environment', 'test');
  });
});
