// Load test environment variables
require('dotenv').config({ path: '.env.test' });

const request = require('supertest');
const express = require('express');

// Import middleware directly for focused testing
const {
  helmetConfig,
  corsConfig,
  csrfProtection,
  generateCsrfToken,
  securityLogger,
  sanitizeRequest,
  createRateLimit
} = require('../middleware/security');

const {
  validateRegistration,
  validateLogin,
  limitRequestSize
} = require('../middleware/validation');

// Mock logger to prevent console output during tests
jest.mock('../utils/logger', () => ({
  warn: jest.fn(),
  error: jest.fn(),
  info: jest.fn()
}));

describe('Security Middleware Integration Tests', () => {
  let app;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    
    // Mock session middleware
    app.use((req, res, next) => {
      req.session = { csrfToken: 'test-csrf-token' };
      next();
    });
  });

  describe('Complete Security Stack', () => {
    test('should apply all security middleware in correct order', async () => {
      // Apply all security middleware
      app.use(helmetConfig);
      app.use(securityLogger);
      app.use(sanitizeRequest);
      app.use(limitRequestSize(1024));
      app.use(generateCsrfToken);
      app.use(csrfProtection);
      
      app.post('/test', validateRegistration, (req, res) => {
        res.json({ success: true, body: req.body });
      });

      const response = await request(app)
        .post('/test')
        .set('X-CSRF-Token', 'test-csrf-token')
        .send({
          email: 'test@example.com',
          password: 'SecurePassword123!',
          confirmPassword: 'SecurePassword123!'
        })
        .expect(200);

      // Check security headers are set
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBe('DENY');
      expect(response.headers['strict-transport-security']).toContain('max-age=31536000');
      
      // Check CSRF token is in headers
      expect(response.headers['x-csrf-token']).toBeDefined();
      
      // Check data was processed correctly
      expect(response.body.success).toBe(true);
      expect(response.body.body.email).toBe('test@example.com');
    });

    test('should reject requests without CSRF token', async () => {
      app.use(helmetConfig);
      app.use(generateCsrfToken);
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

    test('should sanitize malicious input', async () => {
      const { sanitizeObject } = require('../middleware/validation');
      
      // Add body sanitization middleware
      app.use((req, res, next) => {
        if (req.body) {
          req.body = sanitizeObject(req.body);
        }
        next();
      });
      
      app.use(sanitizeRequest);
      app.use(generateCsrfToken);
      app.use(csrfProtection);
      
      // Test endpoint that just returns the sanitized body
      app.post('/test', (req, res) => {
        res.json({ body: req.body });
      });

      const response = await request(app)
        .post('/test')
        .set('X-CSRF-Token', 'test-csrf-token')
        .send({
          email: 'test@example.com<script>alert("xss")</script>',
          content: '<img src="x" onerror="alert(1)">'
        })
        .expect(200);

      // Input should be sanitized
      expect(response.body.body.email).not.toContain('<script>');
      expect(response.body.body.email).not.toContain('alert');
      expect(response.body.body.content).not.toContain('<img');
      expect(response.body.body.content).not.toContain('onerror');
    });

    test('should enforce request size limits', async () => {
      app.use(limitRequestSize(100)); // Very small limit for testing
      
      app.post('/test', (req, res) => {
        res.json({ success: true });
      });

      const largePayload = 'x'.repeat(200);
      
      const response = await request(app)
        .post('/test')
        .send({ data: largePayload })
        .expect(413);

      expect(response.body.error.code).toBe('REQUEST_TOO_LARGE');
    });

    test('should apply rate limiting', async () => {
      const rateLimit = createRateLimit({
        windowMs: 60000,
        max: 2,
        message: 'Rate limit exceeded'
      });
      
      app.use(rateLimit);
      app.get('/test', (req, res) => {
        res.json({ success: true });
      });

      // First two requests should succeed
      await request(app).get('/test').expect(200);
      await request(app).get('/test').expect(200);
      
      // Third request should be rate limited
      const response = await request(app).get('/test').expect(429);
      expect(response.body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    });

    test('should validate input and return proper error format', async () => {
      app.use(generateCsrfToken);
      app.use(csrfProtection);
      
      app.post('/test', validateLogin, (req, res) => {
        res.json({ success: true });
      });

      const response = await request(app)
        .post('/test')
        .set('X-CSRF-Token', 'test-csrf-token')
        .send({
          email: 'invalid-email',
          password: ''
        })
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.details).toBeDefined();
      expect(Array.isArray(response.body.error.details)).toBe(true);
      expect(response.body.error.timestamp).toBeDefined();
    });

    test('should log security events', async () => {
      const logger = require('../utils/logger');
      
      app.use(securityLogger);
      app.use(generateCsrfToken);
      app.use(csrfProtection);
      
      app.post('/auth/login', (req, res) => {
        res.status(401).json({ 
          error: { 
            code: 'AUTH_FAILED',
            message: 'Authentication failed' 
          } 
        });
      });

      await request(app)
        .post('/auth/login')
        .set('X-CSRF-Token', 'test-csrf-token')
        .send({ email: 'test@example.com', password: 'wrong' })
        .expect(401);

      // Should log authentication request
      expect(logger.info).toHaveBeenCalledWith(
        'Authentication request',
        expect.objectContaining({
          method: 'POST',
          path: '/auth/login'
        })
      );

      // Should log failed request
      expect(logger.warn).toHaveBeenCalledWith(
        'Security event - failed request',
        expect.objectContaining({
          statusCode: 401,
          error: 'AUTH_FAILED'
        })
      );
    });
  });

  describe('CORS Integration', () => {
    test('should handle CORS properly', async () => {
      const cors = require('cors');
      app.use(cors(corsConfig));
      
      app.get('/test', (req, res) => {
        res.json({ success: true });
      });

      const response = await request(app)
        .get('/test')
        .set('Origin', 'http://localhost:3000')
        .expect(200);

      expect(response.headers['access-control-allow-origin']).toBe('http://localhost:3000');
      expect(response.headers['access-control-allow-credentials']).toBe('true');
    });
  });

  describe('Error Handling', () => {
    test('should handle middleware errors gracefully', async () => {
      app.use((req, res, next) => {
        const error = new Error('Test middleware error');
        error.status = 500;
        error.code = 'TEST_ERROR';
        next(error);
      });

      // Global error handler
      app.use((err, req, res, next) => {
        res.status(err.status || 500).json({
          error: {
            code: err.code || 'INTERNAL_SERVER_ERROR',
            message: err.message,
            timestamp: new Date().toISOString()
          }
        });
      });

      const response = await request(app)
        .get('/test')
        .expect(500);

      expect(response.body.error.code).toBe('TEST_ERROR');
      expect(response.body.error.message).toBe('Test middleware error');
      expect(response.body.error.timestamp).toBeDefined();
    });
  });
});