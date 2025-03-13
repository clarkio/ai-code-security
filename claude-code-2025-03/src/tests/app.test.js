const request = require('supertest');
const app = require('../app');

// Simple health check test
describe('API Health Check', () => {
  it('should return status 200 and success message', async () => {
    const response = await request(app).get('/api/health');
    
    expect(response.statusCode).toBe(200);
    expect(response.body.success).toBe(true);
    expect(response.body.message).toBe('API is running');
    expect(response.body.timestamp).toBeDefined();
  });
});

// Test for 404 on unknown API route
describe('API 404 Handler', () => {
  it('should return 404 for unknown API route', async () => {
    const response = await request(app).get('/api/unknown-route');
    
    expect(response.statusCode).toBe(404);
    expect(response.body.success).toBe(false);
    expect(response.body.error.message).toBe('Resource not found');
  });
});

// Auth endpoints tests (no actual DB operations)
describe('Auth Routes', () => {
  // Test that login validation works
  it('should validate login input', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .send({
        // Missing password field
        username: 'testuser'
      });
    
    expect(response.statusCode).toBe(400);
    expect(response.body.success).toBe(false);
    expect(response.body.errors).toBeDefined();
  });
  
  // Test that registration validation works
  it('should validate registration input', async () => {
    const response = await request(app)
      .post('/api/auth/register')
      .send({
        username: 'te', // Too short
        email: 'invalid-email',
        password: 'short',
        confirmPassword: 'nomatch'
      });
    
    expect(response.statusCode).toBe(400);
    expect(response.body.success).toBe(false);
    expect(response.body.errors).toBeDefined();
    expect(response.body.errors.length).toBeGreaterThan(0);
  });
});