const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const { app } = require('../src/server');
const User = require('../src/models/User');

let mongoServer;
let server;

// Test user data
const testUser = {
  name: 'Test User',
  email: 'test@example.com',
  password: 'Test123!@#',
  passwordConfirm: 'Test123!@#'
};

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
  server = app.listen(0);
});

afterAll(async () => {
  // Close the server and database connection
  await server.close();
  await mongoose.disconnect();
  await mongoServer.stop();
});

describe('Authentication API', () => {
  describe('POST /api/v1/auth/signup', () => {
    afterEach(async () => {
      // Clean up the test user after each test
      await User.deleteMany({});
    });

    it('should create a new user with valid data', async () => {
      const res = await request(server)
        .post('/api/v1/auth/signup')
        .send(testUser);
      
      expect(res.statusCode).toBe(201);
      expect(res.body.status).toBe('success');
      expect(res.body.data.user.email).toBe(testUser.email);
      expect(res.body.data.user.name).toBe(testUser.name);
      expect(res.body.data.user.password).toBeUndefined();
      expect(res.body.data.token).toBeDefined();
      
      // Verify user is actually in the database
      const user = await User.findOne({ email: testUser.email });
      expect(user).toBeDefined();
      expect(user.email).toBe(testUser.email);
      expect(user.name).toBe(testUser.name);
      expect(user.password).not.toBe(testUser.password); // Should be hashed
    });

    it('should return 400 if email is missing', async () => {
      const invalidUser = { ...testUser, email: '' };
      const res = await request(server)
        .post('/api/v1/auth/signup')
        .send(invalidUser);
      
      expect(res.statusCode).toBe(400);
      expect(res.body.status).toBe('fail');
      expect(res.body.message).toContain('Please provide a valid email');
    });

    it('should return 400 if password is too short', async () => {
      const invalidUser = { ...testUser, password: 'short', passwordConfirm: 'short' };
      const res = await request(server)
        .post('/api/v1/auth/signup')
        .send(invalidUser);
      
      expect(res.statusCode).toBe(400);
      expect(res.body.status).toBe('fail');
      expect(res.body.message).toContain('Password must be at least 12 characters long');
    });

    it('should return 400 if passwords do not match', async () => {
      const invalidUser = { ...testUser, passwordConfirm: 'DifferentPass123!' };
      const res = await request(server)
        .post('/api/v1/auth/signup')
        .send(invalidUser);
      
      expect(res.statusCode).toBe(400);
      expect(res.body.status).toBe('fail');
      expect(res.body.message).toContain('Passwords do not match');
    });

    it('should return 400 if email is already in use', async () => {
      // First create a user
      await request(server)
        .post('/api/v1/auth/signup')
        .send(testUser);
      
      // Try to create another user with the same email
      const res = await request(server)
        .post('/api/v1/auth/signup')
        .send(testUser);
      
      expect(res.statusCode).toBe(400);
      expect(res.body.status).toBe('fail');
      expect(res.body.message).toContain('Email already in use');
    });
  });

  describe('POST /api/v1/auth/login', () => {
    beforeEach(async () => {
      // Create a test user before login tests
      await request(server)
        .post('/api/v1/auth/signup')
        .send(testUser);
    });

    afterEach(async () => {
      // Clean up the test user after each test
      await User.deleteMany({});
    });

    it('should log in with correct credentials', async () => {
      const res = await request(server)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password
        });
      
      expect(res.statusCode).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data.user.email).toBe(testUser.email);
      expect(res.body.data.token).toBeDefined();
      
      // Check if the token is set in cookies
      expect(res.headers['set-cookie']).toBeDefined();
      const cookies = res.headers['set-cookie'];
      const jwtCookie = cookies.find(cookie => cookie.startsWith('jwt='));
      expect(jwtCookie).toBeDefined();
    });

    it('should return 401 with incorrect password', async () => {
      const res = await request(server)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: 'wrongpassword'
        });
      
      expect(res.statusCode).toBe(401);
      expect(res.body.status).toBe('fail');
      expect(res.body.message).toBe('Incorrect email or password');
    });

    it('should return 401 with non-existent email', async () => {
      const res = await request(server)
        .post('/api/v1/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: testUser.password
        });
      
      expect(res.statusCode).toBe(401);
      expect(res.body.status).toBe('fail');
      expect(res.body.message).toBe('Incorrect email or password');
    });
  });

  describe('GET /api/v1/auth/logout', () => {
    let authToken;
    
    beforeEach(async () => {
      // Sign up and log in a test user
      await request(server)
        .post('/api/v1/auth/signup')
        .send(testUser);
      
      const loginRes = await request(server)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password
        });
      
      authToken = loginRes.body.data.token;
    });

    afterEach(async () => {
      // Clean up the test user after each test
      await User.deleteMany({});
    });

    it('should log out a logged-in user', async () => {
      const res = await request(server)
        .get('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.status).toBe('success');
      
      // Check if the JWT cookie is cleared
      expect(res.headers['set-cookie']).toBeDefined();
      const cookies = res.headers['set-cookie'];
      const jwtCookie = cookies.find(cookie => 
        cookie.startsWith('jwt=loggedout') || 
        cookie.includes('Expires=Thu, 01 Jan 1970')
      );
      expect(jwtCookie).toBeDefined();
    });
  });
});
