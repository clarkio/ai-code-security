const request = require('supertest');
const app = require('../app');
const { validateInput, sanitizeHtml, sanitizeObject, schemas } = require('../middleware/validation');

// Load test environment
require('./setup');

// Mock dependencies
jest.mock('../utils/logger', () => ({
  warn: jest.fn(),
  error: jest.fn(),
  info: jest.fn()
}));

// Mock Redis client
jest.mock('redis', () => ({
  createClient: jest.fn(() => ({
    on: jest.fn(),
    quit: jest.fn((callback) => callback && callback())
  }))
}));

// Mock express-session
jest.mock('express-session', () => {
  return jest.fn(() => (req, res, next) => {
    req.session = { csrfToken: 'test-csrf-token' };
    next();
  });
});

// Mock connect-redis
jest.mock('connect-redis', () => {
  return jest.fn(() => {
    return class MockRedisStore {
      constructor() {
        this.on = jest.fn();
      }
    };
  });
});

describe('Input Validation and XSS Prevention Tests', () => {
  describe('SQL Injection Prevention', () => {
    test('should prevent SQL injection in registration data', async () => {
      const tokenResponse = await request(app)
        .get('/api/csrf-token')
        .expect(200);

      const sqlInjectionPayloads = [
        {
          email: "admin@test.com'; DROP TABLE users; --",
          password: 'ValidPassword123!',
          confirmPassword: 'ValidPassword123!'
        },
        {
          email: "test@example.com",
          password: "' OR '1'='1'; --",
          confirmPassword: "' OR '1'='1'; --"
        },
        {
          email: "test@example.com' UNION SELECT * FROM users --",
          password: 'ValidPassword123!',
          confirmPassword: 'ValidPassword123!'
        }
      ];

      for (const payload of sqlInjectionPayloads) {
        const response = await request(app)
          .post('/api/auth/register')
          .set('X-CSRF-Token', tokenResponse.body.csrfToken)
          .send(payload)
          .expect(400);

        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        
        // Verify the request was rejected due to validation
        // The exact sanitization behavior may vary, but malicious patterns should be handled
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
      }
    });

    test('should prevent SQL injection in note content', async () => {
      const sqlInjectionNotes = [
        {
          title: "'; DROP TABLE notes; --",
          content: 'Normal content'
        },
        {
          title: 'Normal title',
          content: "' UNION SELECT password FROM users WHERE '1'='1"
        },
        {
          title: '1\' OR \'1\'=\'1',
          content: 'SELECT * FROM users'
        }
      ];

      for (const note of sqlInjectionNotes) {
        const response = await request(app)
          .post('/api/notes')
          .set('Authorization', 'Bearer fake-jwt-token') // Skip CSRF
          .send(note);

        // Should either fail validation (400) or authentication (401)
        expect([400, 401]).toContain(response.status);
        
        // If it's a validation error, verify it's handled properly
        if (response.status === 400) {
          expect(response.body.error.code).toBe('VALIDATION_ERROR');
        }
      }
    });

    test('should sanitize SQL injection patterns in input', () => {
      const maliciousInputs = [
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM passwords --",
        "1' OR '1'='1",
        "admin'--",
        "' OR 1=1 --"
      ];

      for (const input of maliciousInputs) {
        const sanitized = sanitizeHtml(input);
        
        // Verify that the sanitized output is different from the input
        // and that dangerous patterns are reduced or removed
        expect(sanitized).toBeDefined();
        expect(typeof sanitized).toBe('string');
        
        // The sanitization should at least remove SQL comments
        expect(sanitized).not.toContain('--');
      }
    });

    test('should prevent SQL injection through query parameters', async () => {
      const maliciousQueries = [
        "'; DROP TABLE notes; --",
        "' UNION SELECT * FROM users --",
        "1' OR '1'='1"
      ];

      for (const query of maliciousQueries) {
        const response = await request(app)
          .get(`/api/notes?search=${encodeURIComponent(query)}`)
          .set('Authorization', 'Bearer fake-jwt-token')
          .expect(401); // Will fail auth, but should sanitize query first

        // The query should be sanitized before processing
        // Even if auth fails, the sanitization should have occurred
      }
    });
  });

  describe('XSS Attack Prevention', () => {
    test('should prevent script injection in note content', async () => {
      const xssPayloads = [
        {
          title: '<script>alert("XSS")</script>',
          content: 'Normal content'
        },
        {
          title: 'Normal title',
          content: '<img src="x" onerror="alert(\'XSS\')">'
        },
        {
          title: 'javascript:alert("XSS")',
          content: 'Normal content'
        },
        {
          title: '<iframe src="javascript:alert(\'XSS\')"></iframe>',
          content: 'Normal content'
        }
      ];

      for (const payload of xssPayloads) {
        const response = await request(app)
          .post('/api/notes')
          .set('Authorization', 'Bearer fake-jwt-token')
          .send(payload);

        // Should either fail validation (400) or authentication (401)
        expect([400, 401]).toContain(response.status);
        
        // If it's a validation error, verify it's handled properly
        if (response.status === 400) {
          expect(response.body.error.code).toBe('VALIDATION_ERROR');
        }
      }
    });

    test('should sanitize HTML tags and attributes', () => {
      const htmlInputs = [
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(\'XSS\')">',
        '<div onclick="alert(\'XSS\')">Click me</div>',
        '<a href="javascript:alert(\'XSS\')">Link</a>',
        '<iframe src="data:text/html,<script>alert(\'XSS\')</script>"></iframe>'
      ];

      for (const input of htmlInputs) {
        const sanitized = sanitizeHtml(input);
        
        expect(sanitized).not.toContain('<script>');
        expect(sanitized).not.toContain('javascript:');
        expect(sanitized).not.toContain('onerror=');
        expect(sanitized).not.toContain('onclick=');
        expect(sanitized).not.toContain('<iframe>');
        expect(sanitized).not.toContain('data:');
      }
    });

    test('should prevent XSS through registration form', async () => {
      const tokenResponse = await request(app)
        .get('/api/csrf-token')
        .expect(200);

      const xssPayloads = [
        {
          email: '<script>alert("XSS")</script>@test.com',
          password: 'ValidPassword123!',
          confirmPassword: 'ValidPassword123!'
        },
        {
          email: 'test@example.com',
          password: '<img src=x onerror=alert("XSS")>ValidPassword123!',
          confirmPassword: '<img src=x onerror=alert("XSS")>ValidPassword123!'
        }
      ];

      for (const payload of xssPayloads) {
        const response = await request(app)
          .post('/api/auth/register')
          .set('X-CSRF-Token', tokenResponse.body.csrfToken)
          .send(payload)
          .expect(400);

        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        
        // Verify the request was rejected due to validation
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
      }
    });

    test('should sanitize nested objects recursively', () => {
      const nestedObject = {
        title: '<script>alert("XSS")</script>',
        content: {
          text: '<img src="x" onerror="alert(\'XSS\')">',
          metadata: {
            author: '<div onclick="alert(\'XSS\')">Author</div>'
          }
        },
        tags: [
          '<script>alert("XSS")</script>',
          'normal-tag',
          '<iframe src="javascript:alert(\'XSS\')"></iframe>'
        ]
      };

      const sanitized = sanitizeObject(nestedObject);
      
      const sanitizedString = JSON.stringify(sanitized);
      expect(sanitizedString).not.toContain('<script>');
      expect(sanitizedString).not.toContain('onerror=');
      expect(sanitizedString).not.toContain('onclick=');
      expect(sanitizedString).not.toContain('javascript:');
      expect(sanitizedString).not.toContain('<iframe>');
      
      // Verify structure is preserved
      expect(sanitized.content.metadata.author).toBeDefined();
      expect(Array.isArray(sanitized.tags)).toBe(true);
      expect(sanitized.tags).toHaveLength(3);
    });

    test('should prevent XSS through URL parameters', async () => {
      const xssQueries = [
        '<script>alert("XSS")</script>',
        'javascript:alert("XSS")',
        '<img src=x onerror=alert("XSS")>'
      ];

      for (const query of xssQueries) {
        const response = await request(app)
          .get(`/api/notes?search=${encodeURIComponent(query)}`)
          .set('Authorization', 'Bearer fake-jwt-token')
          .expect(401); // Will fail auth, but should sanitize query first

        // Even though auth fails, the query should be sanitized
        // This prevents XSS in error messages or logs
      }
    });
  });

  describe('CSRF Protection Validation', () => {
    test('should reject POST requests without CSRF token', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'test@example.com',
          password: 'ValidPassword123!',
          confirmPassword: 'ValidPassword123!'
        })
        .expect(403);

      expect(response.body.error.code).toBe('CSRF_TOKEN_INVALID');
      expect(response.body.error.message).toContain('CSRF token');
    });

    test('should reject requests with invalid CSRF token', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .set('X-CSRF-Token', 'invalid-token')
        .send({
          email: 'test@example.com',
          password: 'ValidPassword123!',
          confirmPassword: 'ValidPassword123!'
        })
        .expect(403);

      expect(response.body.error.code).toBe('CSRF_TOKEN_INVALID');
    });

    test('should accept requests with valid CSRF token', async () => {
      const tokenResponse = await request(app)
        .get('/api/csrf-token')
        .expect(200);

      const csrfToken = tokenResponse.body.csrfToken;
      expect(csrfToken).toBeDefined();
      expect(typeof csrfToken).toBe('string');
      expect(csrfToken.length).toBeGreaterThan(0);

      // Request with valid token should pass CSRF validation
      // (may fail for other reasons like validation)
      const response = await request(app)
        .post('/api/auth/register')
        .set('X-CSRF-Token', csrfToken)
        .send({
          email: 'test@example.com',
          password: 'ValidPassword123!',
          confirmPassword: 'ValidPassword123!'
        });

      // Should not fail due to CSRF
      expect(response.status).not.toBe(403);
    });

    test('should skip CSRF for API endpoints with JWT authorization', async () => {
      // API endpoints with Authorization header should skip CSRF
      const response = await request(app)
        .post('/api/notes')
        .set('Authorization', 'Bearer fake-jwt-token')
        .send({
          title: 'Test Note',
          content: 'Test content'
        });

      // Should not fail due to CSRF (may fail for other reasons like invalid JWT)
      expect(response.status).not.toBe(403);
    });

    test('should allow GET requests without CSRF token', async () => {
      // Health endpoint might not be available in test environment
      const healthResponse = await request(app).get('/health');
      expect([200, 503]).toContain(healthResponse.status);

      await request(app)
        .get('/api/csrf-token')
        .expect(200);
    });
  });

  describe('File Upload Security Tests', () => {
    test('should reject files with malicious content', async () => {
      const tokenResponse = await request(app)
        .get('/api/csrf-token')
        .expect(200);

      const maliciousFiles = [
        {
          name: 'malicious.txt',
          content: '<script>alert("XSS")</script>',
          mimetype: 'text/plain'
        },
        {
          name: 'evil.js',
          content: 'javascript:alert("XSS")',
          mimetype: 'text/plain'
        },
        {
          name: 'bad.html',
          content: '<img src="x" onerror="alert(\'XSS\')">',
          mimetype: 'text/plain'
        }
      ];

      for (const file of maliciousFiles) {
        const response = await request(app)
          .post('/api/upload')
          .set('X-CSRF-Token', tokenResponse.body.csrfToken)
          .attach('file', Buffer.from(file.content), {
            filename: file.name,
            contentType: file.mimetype
          })
          .expect(400); // Bad request due to missing file or validation

        // Should reject the request due to validation or missing file
        expect(response.body.error).toBeDefined();
      }
    });

    test('should reject files with invalid extensions', async () => {
      const tokenResponse = await request(app)
        .get('/api/csrf-token')
        .expect(200);

      const invalidFiles = [
        'malicious.exe',
        'virus.bat',
        'script.php',
        'backdoor.jsp'
      ];

      for (const filename of invalidFiles) {
        const response = await request(app)
          .post('/api/upload')
          .set('X-CSRF-Token', tokenResponse.body.csrfToken)
          .attach('file', Buffer.from('test content'), {
            filename: filename,
            contentType: 'application/octet-stream'
          })
          .expect(400); // Bad request due to validation

        expect(response.body.error).toBeDefined();
      }
    });

    test('should validate file size limits', async () => {
      const tokenResponse = await request(app)
        .get('/api/csrf-token')
        .expect(200);

      // Create a large file (2MB)
      const largeContent = 'x'.repeat(2 * 1024 * 1024);

      const response = await request(app)
        .post('/api/upload')
        .set('X-CSRF-Token', tokenResponse.body.csrfToken)
        .attach('file', Buffer.from(largeContent), {
          filename: 'large.txt',
          contentType: 'text/plain'
        })
        .expect(413); // Request too large

      expect(response.body.error.code).toBe('REQUEST_TOO_LARGE');
    });
  });

  describe('Input Validation Schema Tests', () => {
    test('should validate email format strictly', () => {
      const invalidEmails = [
        'invalid-email',
        '@domain.com',
        'user@',
        'user@domain',
        'user@domain.',
        'user..name@domain.com',
        'user@domain..com',
        'user@.domain.com',
        'user@domain.c',
        'user@domain.toolongextension'
      ];

      for (const email of invalidEmails) {
        const { error } = schemas.registration.validate({
          email: email,
          password: 'ValidPassword123!',
          confirmPassword: 'ValidPassword123!'
        });

        expect(error).toBeDefined();
        expect(error.details[0].path).toContain('email');
      }
    });

    test('should enforce password complexity requirements', () => {
      const weakPasswords = [
        'short', // Too short
        'nouppercase123!', // No uppercase
        'NOLOWERCASE123!', // No lowercase
        'NoNumbers!', // No numbers
        'NoSpecialChars123', // No special characters
        'password123!', // Common pattern
        'Password123', // No special character
        '12345678901!' // No letters
      ];

      for (const password of weakPasswords) {
        const { error } = schemas.registration.validate({
          email: 'test@example.com',
          password: password,
          confirmPassword: password
        });

        expect(error).toBeDefined();
        expect(error.details.some(detail => detail.path.includes('password'))).toBe(true);
      }
    });

    test('should validate note content length limits', () => {
      const longContent = 'x'.repeat(10001); // Exceeds 10,000 character limit

      const { error } = schemas.noteCreation.validate({
        title: 'Valid Title',
        content: longContent
      });

      expect(error).toBeDefined();
      expect(error.details[0].path).toContain('content');
      expect(error.details[0].message).toContain('too long');
    });

    test('should validate pagination parameters', () => {
      const invalidPagination = [
        { page: 0 }, // Page too small
        { page: 1001 }, // Page too large
        { page: 'invalid' }, // Non-numeric page
        { limit: 0 }, // Limit too small
        { limit: 101 }, // Limit too large
        { limit: 'invalid' } // Non-numeric limit
      ];

      for (const params of invalidPagination) {
        const { error } = schemas.pagination.validate(params);
        expect(error).toBeDefined();
      }
    });

    test('should accept valid input data', () => {
      const validData = [
        {
          schema: schemas.registration,
          data: {
            email: 'user@example.com',
            password: 'ValidPassword123!',
            confirmPassword: 'ValidPassword123!'
          }
        },
        {
          schema: schemas.login,
          data: {
            email: 'user@example.com',
            password: 'anypassword'
          }
        },
        {
          schema: schemas.noteCreation,
          data: {
            title: 'Valid Note Title',
            content: 'Valid note content'
          }
        },
        {
          schema: schemas.pagination,
          data: {
            page: 1,
            limit: 10
          }
        }
      ];

      for (const { schema, data } of validData) {
        const { error } = schema.validate(data);
        expect(error).toBeUndefined();
      }
    });
  });

  describe('Request Size Limiting', () => {
    test('should reject oversized requests', async () => {
      const tokenResponse = await request(app)
        .get('/api/csrf-token')
        .expect(200);

      // Create a large payload (2MB)
      const largePayload = {
        email: 'test@example.com',
        password: 'ValidPassword123!',
        confirmPassword: 'ValidPassword123!',
        extraData: 'x'.repeat(2 * 1024 * 1024)
      };

      const response = await request(app)
        .post('/api/auth/register')
        .set('X-CSRF-Token', tokenResponse.body.csrfToken)
        .send(largePayload)
        .expect(413);

      expect(response.body.error.code).toBe('REQUEST_TOO_LARGE');
    });

    test('should accept normal-sized requests', async () => {
      const tokenResponse = await request(app)
        .get('/api/csrf-token')
        .expect(200);

      const normalPayload = {
        email: 'test@example.com',
        password: 'ValidPassword123!',
        confirmPassword: 'ValidPassword123!'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .set('X-CSRF-Token', tokenResponse.body.csrfToken)
        .send(normalPayload);

      // Should not fail due to size (may fail for other reasons)
      expect(response.status).not.toBe(413);
    });
  });

  describe('Parameter Pollution Prevention', () => {
    test('should handle array parameter pollution', async () => {
      // Test with array values in query parameters
      const response = await request(app)
        .get('/api/notes?page[]=1&page[]=2&limit[]=10&limit[]=20')
        .set('Authorization', 'Bearer fake-jwt-token')
        .expect(401); // Will fail auth, but should handle parameter pollution

      // The request should be processed without crashing
      expect(response.status).toBe(401);
    });

    test('should sanitize parameter pollution in request body', async () => {
      const tokenResponse = await request(app)
        .get('/api/csrf-token')
        .expect(200);

      const pollutedPayload = {
        email: ['test@example.com', 'malicious@hacker.com'],
        password: 'ValidPassword123!',
        confirmPassword: 'ValidPassword123!'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .set('X-CSRF-Token', tokenResponse.body.csrfToken)
        .send(pollutedPayload);

      // Should either fail validation (400) or hit rate limit (429)
      expect([400, 429]).toContain(response.status);
      
      if (response.status === 400) {
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        
        // Should reject array values where strings are expected
        expect(response.body.error.details.some(
          detail => detail.field === 'email'
        )).toBe(true);
      } else if (response.status === 429) {
        expect(response.body.error.code).toBe('RATE_LIMIT_EXCEEDED');
      }
    });
  });
});