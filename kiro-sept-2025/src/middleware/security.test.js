// Load test environment variables
require('dotenv').config({ path: '.env.test' });

const request = require('supertest');
const express = require('express');
const {
  helmetConfig,
  authRateLimit,
  apiRateLimit,
  uploadRateLimit,
  corsConfig,
  csrfProtection,
  generateCsrfToken,
  securityLogger,
  sanitizeRequest,
  createRateLimit
} = require('./security');

// Mock logger to prevent console output during tests
jest.mock('../utils/logger', () => ({
  warn: jest.fn(),
  error: jest.fn(),
  info: jest.fn()
}));

describe('Security Middleware', () => {
  let app;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
  });

  describe('Helmet Configuration', () => {
    test('should set security headers', async () => {
      app.use(helmetConfig);
      app.get('/test', (req, res) => {
        res.json({ success: true });
      });

      const response = await request(app)
        .get('/test')
        .expect(200);

      // Check for security headers
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBe('DENY');
      expect(response.headers['x-xss-protection']).toBe('0');
      expect(response.headers['strict-transport-security']).toContain('max-age=31536000');
      expect(response.headers['content-security-policy']).toContain("default-src 'self'");
    });
  });

  describe('Rate Limiting', () => {
    test('should create rate limit with default options', () => {
      const rateLimit = createRateLimit();
      expect(typeof rateLimit).toBe('function');
    });

    test('should create rate limit with custom options', () => {
      const rateLimit = createRateLimit({
        windowMs: 60000,
        max: 10,
        message: 'Custom rate limit message'
      });
      expect(typeof rateLimit).toBe('function');
    });

    test('should apply auth rate limiting', async () => {
      // Create a more restrictive rate limit for testing
      const testRateLimit = createRateLimit({
        windowMs: 60000,
        max: 2, // Only allow 2 requests
        message: 'Too many authentication attempts'
      });
      
      app.use('/auth', testRateLimit);
      app.post('/auth/login', (req, res) => {
        res.json({ success: true });
      });

      // Make requests up to the limit
      await request(app)
        .post('/auth/login')
        .send({ email: 'test@example.com', password: 'password' })
        .expect(200);

      await request(app)
        .post('/auth/login')
        .send({ email: 'test@example.com', password: 'password' })
        .expect(200);

      // The 3rd request should be rate limited
      const response = await request(app)
        .post('/auth/login')
        .send({ email: 'test@example.com', password: 'password' })
        .expect(429);

      expect(response.body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    });

    test('should apply API rate limiting', async () => {
      app.use('/api', apiRateLimit);
      app.get('/api/test', (req, res) => {
        res.json({ success: true });
      });

      // Make multiple requests (should allow more than auth rate limit)
      for (let i = 0; i < 10; i++) {
        await request(app)
          .get('/api/test')
          .expect(200);
      }
    });
  });

  describe('CSRF Protection', () => {
    beforeEach(() => {
      // Mock session middleware
      app.use((req, res, next) => {
        req.session = { csrfToken: 'test-csrf-token' };
        next();
      });
    });

    test('should allow GET requests without CSRF token', async () => {
      app.use(csrfProtection);
      app.get('/test', (req, res) => {
        res.json({ success: true });
      });

      await request(app)
        .get('/test')
        .expect(200);
    });

    test('should allow POST requests with valid CSRF token', async () => {
      app.use(csrfProtection);
      app.post('/test', (req, res) => {
        res.json({ success: true });
      });

      await request(app)
        .post('/test')
        .set('X-CSRF-Token', 'test-csrf-token')
        .send({ data: 'test' })
        .expect(200);
    });

    test('should reject POST requests without CSRF token', async () => {
      app.use(csrfProtection);
      app.post('/test', (req, res) => {
        res.json({ success: true });
      });

      const response = await request(app)
        .post('/test')
        .send({ data: 'test' })
        .expect(403);

      expect(response.body.error.code).toBe('CSRF_TOKEN_INVALID');
    });

    test('should reject POST requests with invalid CSRF token', async () => {
      app.use(csrfProtection);
      app.post('/test', (req, res) => {
        res.json({ success: true });
      });

      const response = await request(app)
        .post('/test')
        .set('X-CSRF-Token', 'invalid-token')
        .send({ data: 'test' })
        .expect(403);

      expect(response.body.error.code).toBe('CSRF_TOKEN_INVALID');
    });

    test('should skip CSRF for API endpoints with JWT', async () => {
      app.use(csrfProtection);
      app.post('/api/test', (req, res) => {
        res.json({ success: true });
      });

      await request(app)
        .post('/api/test')
        .set('Authorization', 'Bearer jwt-token')
        .send({ data: 'test' })
        .expect(200);
    });
  });

  describe('CSRF Token Generation', () => {
    test('should generate CSRF token for new session', async () => {
      app.use((req, res, next) => {
        req.session = {};
        next();
      });
      app.use(generateCsrfToken);
      app.get('/test', (req, res) => {
        res.json({ success: true, csrfToken: req.session.csrfToken });
      });

      const response = await request(app)
        .get('/test')
        .expect(200);

      expect(response.body.csrfToken).toBeDefined();
      expect(response.headers['x-csrf-token']).toBeDefined();
    });

    test('should reuse existing CSRF token', async () => {
      const existingToken = 'existing-csrf-token';
      app.use((req, res, next) => {
        req.session = { csrfToken: existingToken };
        next();
      });
      app.use(generateCsrfToken);
      app.get('/test', (req, res) => {
        res.json({ success: true, csrfToken: req.session.csrfToken });
      });

      const response = await request(app)
        .get('/test')
        .expect(200);

      expect(response.body.csrfToken).toBe(existingToken);
      expect(response.headers['x-csrf-token']).toBe(existingToken);
    });
  });

  describe('Security Logger', () => {
    test('should log authentication requests', async () => {
      const logger = require('../utils/logger');
      app.use(securityLogger);
      app.post('/auth/login', (req, res) => {
        res.json({ success: true });
      });

      await request(app)
        .post('/auth/login')
        .send({ email: 'test@example.com' })
        .expect(200);

      expect(logger.info).toHaveBeenCalledWith(
        'Authentication request',
        expect.objectContaining({
          method: 'POST',
          path: '/auth/login'
        })
      );
    });

    test('should log failed requests', async () => {
      const logger = require('../utils/logger');
      app.use(securityLogger);
      app.post('/test', (req, res) => {
        res.status(400).json({ 
          error: { 
            code: 'VALIDATION_ERROR',
            message: 'Test error' 
          } 
        });
      });

      await request(app)
        .post('/test')
        .send({ data: 'test' })
        .expect(400);

      expect(logger.warn).toHaveBeenCalledWith(
        'Security event - failed request',
        expect.objectContaining({
          statusCode: 400,
          error: 'VALIDATION_ERROR'
        })
      );
    });
  });

  describe('Request Sanitization', () => {
    test('should remove null bytes from parameters', async () => {
      app.use(sanitizeRequest);
      app.get('/user/:id', (req, res) => {
        res.json({ userId: req.params.id });
      });

      // Simulate the sanitization by testing the middleware directly
      const mockReq = {
        params: { id: '123\x00malicious' },
        query: {},
        path: '/user/123'
      };
      const mockRes = {};
      const mockNext = jest.fn();

      sanitizeRequest(mockReq, mockRes, mockNext);

      expect(mockReq.params.id).toBe('123malicious');
      expect(mockReq.params.id).not.toContain('\x00');
      expect(mockNext).toHaveBeenCalled();
    });

    test('should remove null bytes from query parameters', async () => {
      app.use(sanitizeRequest);
      app.get('/search', (req, res) => {
        res.json({ query: req.query.q });
      });

      // Test the middleware directly
      const mockReq = {
        params: {},
        query: { q: 'test\x00malicious', page: 1 },
        path: '/search'
      };
      const mockRes = {};
      const mockNext = jest.fn();

      sanitizeRequest(mockReq, mockRes, mockNext);

      expect(mockReq.query.q).toBe('testmalicious');
      expect(mockReq.query.q).not.toContain('\x00');
      expect(mockReq.query.page).toBe(1); // Non-string should remain unchanged
      expect(mockNext).toHaveBeenCalled();
    });

    test('should handle non-string query parameters', async () => {
      app.use(sanitizeRequest);
      app.get('/search', (req, res) => {
        res.json({ 
          page: req.query.page,
          limit: req.query.limit 
        });
      });

      const response = await request(app)
        .get('/search?page=1&limit=10')
        .expect(200);

      expect(response.body.page).toBe('1');
      expect(response.body.limit).toBe('10');
    });
  });

  describe('CORS Configuration', () => {
    test('should have proper CORS configuration structure', () => {
      expect(corsConfig).toHaveProperty('origin');
      expect(corsConfig).toHaveProperty('credentials', true);
      expect(corsConfig).toHaveProperty('methods');
      expect(corsConfig).toHaveProperty('allowedHeaders');
      expect(corsConfig).toHaveProperty('exposedHeaders');
      expect(corsConfig).toHaveProperty('maxAge', 86400);
    });

    test('should allow requests with no origin', (done) => {
      corsConfig.origin(null, (err, allowed) => {
        expect(err).toBeNull();
        expect(allowed).toBe(true);
        done();
      });
    });

    test('should allow localhost origins by default', (done) => {
      corsConfig.origin('http://localhost:3000', (err, allowed) => {
        expect(err).toBeNull();
        expect(allowed).toBe(true);
        done();
      });
    });

    test('should reject unauthorized origins', (done) => {
      corsConfig.origin('http://malicious-site.com', (err, allowed) => {
        expect(err).toBeInstanceOf(Error);
        expect(err.message).toBe('Not allowed by CORS');
        done();
      });
    });
  });

  describe('Error Response Format', () => {
    test('should return properly formatted rate limit error', async () => {
      const rateLimit = createRateLimit({ max: 1, windowMs: 60000 });
      app.use(rateLimit);
      app.get('/test', (req, res) => {
        res.json({ success: true });
      });

      // First request should succeed
      await request(app).get('/test').expect(200);

      // Second request should be rate limited
      const response = await request(app).get('/test').expect(429);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toHaveProperty('code', 'RATE_LIMIT_EXCEEDED');
      expect(response.body.error).toHaveProperty('message');
      expect(response.body.error).toHaveProperty('retryAfter');
      expect(response.body.error).toHaveProperty('timestamp');
    });

    test('should return properly formatted CSRF error', async () => {
      app.use((req, res, next) => {
        req.session = { csrfToken: 'valid-token' };
        next();
      });
      app.use(csrfProtection);
      app.post('/test', (req, res) => {
        res.json({ success: true });
      });

      const response = await request(app)
        .post('/test')
        .send({ data: 'test' })
        .expect(403);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toHaveProperty('code', 'CSRF_TOKEN_INVALID');
      expect(response.body.error).toHaveProperty('message', 'Invalid or missing CSRF token');
      expect(response.body.error).toHaveProperty('timestamp');
    });
  });
});