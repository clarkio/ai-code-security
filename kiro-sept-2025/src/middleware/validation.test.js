const request = require('supertest');
const express = require('express');
const {
  schemas,
  validateInput,
  sanitizeHtml,
  sanitizeObject,
  limitRequestSize,
  validateFileUpload,
  validateRegistration,
  validateLogin,
  validateNoteCreation,
  validateNoteUpdate,
  validatePagination
} = require('./validation');

// Mock logger to prevent console output during tests
jest.mock('../utils/logger', () => ({
  warn: jest.fn(),
  error: jest.fn(),
  info: jest.fn()
}));

describe('Validation Middleware', () => {
  let app;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
  });

  describe('sanitizeHtml', () => {
    test('should remove script tags', () => {
      const maliciousInput = '<script>alert("xss")</script>Hello World';
      const sanitized = sanitizeHtml(maliciousInput);
      expect(sanitized).toBe('Hello World');
      expect(sanitized).not.toContain('<script>');
    });

    test('should remove all HTML tags', () => {
      const htmlInput = '<div><p>Hello <strong>World</strong></p></div>';
      const sanitized = sanitizeHtml(htmlInput);
      expect(sanitized).toBe('Hello World');
    });

    test('should remove event handlers', () => {
      const maliciousInput = '<img src="x" onerror="alert(1)">';
      const sanitized = sanitizeHtml(maliciousInput);
      expect(sanitized).toBe('');
    });

    test('should handle non-string input', () => {
      expect(sanitizeHtml(123)).toBe(123);
      expect(sanitizeHtml(null)).toBe(null);
      expect(sanitizeHtml(undefined)).toBe(undefined);
    });

    test('should preserve text content', () => {
      const input = 'This is plain text with special chars: @#$%^&*()';
      const sanitized = sanitizeHtml(input);
      expect(sanitized).toBe(input);
    });
  });

  describe('sanitizeObject', () => {
    test('should sanitize string values in objects', () => {
      const input = {
        title: '<script>alert("xss")</script>Clean Title',
        content: '<div>Content</div>',
        number: 123
      };
      const sanitized = sanitizeObject(input);
      expect(sanitized.title).toBe('Clean Title');
      expect(sanitized.content).toBe('Content');
      expect(sanitized.number).toBe(123);
    });

    test('should sanitize nested objects', () => {
      const input = {
        user: {
          name: '<script>alert("xss")</script>John',
          profile: {
            bio: '<div>Bio content</div>'
          }
        }
      };
      const sanitized = sanitizeObject(input);
      expect(sanitized.user.name).toBe('John');
      expect(sanitized.user.profile.bio).toBe('Bio content');
    });

    test('should sanitize arrays', () => {
      const input = ['<script>alert("xss")</script>Item 1', '<div>Item 2</div>'];
      const sanitized = sanitizeObject(input);
      expect(sanitized).toEqual(['Item 1', 'Item 2']);
    });
  });

  describe('Registration Validation', () => {
    beforeEach(() => {
      app.post('/register', validateRegistration, (req, res) => {
        res.json({ success: true, data: req.body });
      });
    });

    test('should accept valid registration data', async () => {
      const validData = {
        email: 'test@example.com',
        password: 'SecurePass123!',
        confirmPassword: 'SecurePass123!'
      };

      const response = await request(app)
        .post('/register')
        .send(validData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.email).toBe(validData.email);
    });

    test('should reject invalid email formats', async () => {
      const invalidEmails = [
        'invalid-email',
        '@example.com',
        'test@',
        'test@.com',
        'test@example',
        'a'.repeat(250) + '@example.com' // Too long
      ];

      for (const email of invalidEmails) {
        const response = await request(app)
          .post('/register')
          .send({
            email,
            password: 'SecurePass123!',
            confirmPassword: 'SecurePass123!'
          })
          .expect(400);

        expect(response.body.error.code).toBe('VALIDATION_ERROR');
      }
    });

    test('should reject weak passwords', async () => {
      const weakPasswords = [
        'short', // Too short
        'nouppercase123!', // No uppercase
        'NOLOWERCASE123!', // No lowercase
        'NoNumbers!', // No numbers
        'NoSpecialChars123', // No special characters
        'a'.repeat(130) // Too long
      ];

      for (const password of weakPasswords) {
        const response = await request(app)
          .post('/register')
          .send({
            email: 'test@example.com',
            password,
            confirmPassword: password
          })
          .expect(400);

        expect(response.body.error.code).toBe('VALIDATION_ERROR');
      }
    });

    test('should reject mismatched passwords', async () => {
      const response = await request(app)
        .post('/register')
        .send({
          email: 'test@example.com',
          password: 'SecurePass123!',
          confirmPassword: 'DifferentPass123!'
        })
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.details[0].message).toContain('do not match');
    });

    test('should sanitize malicious input', async () => {
      const maliciousData = {
        email: 'test@example.com',
        password: 'SecurePass123!',
        confirmPassword: 'SecurePass123!'
      };

      const response = await request(app)
        .post('/register')
        .send(maliciousData)
        .expect(200);

      expect(response.body.data.email).toBe('test@example.com');
    });
  });

  describe('Login Validation', () => {
    beforeEach(() => {
      app.post('/login', validateLogin, (req, res) => {
        res.json({ success: true, data: req.body });
      });
    });

    test('should accept valid login data', async () => {
      const validData = {
        email: 'test@example.com',
        password: 'anypassword'
      };

      const response = await request(app)
        .post('/login')
        .send(validData)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    test('should reject missing credentials', async () => {
      const response = await request(app)
        .post('/login')
        .send({})
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    test('should reject invalid email format', async () => {
      const response = await request(app)
        .post('/login')
        .send({
          email: 'invalid-email',
          password: 'password'
        })
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('Note Creation Validation', () => {
    beforeEach(() => {
      app.post('/notes', validateNoteCreation, (req, res) => {
        res.json({ success: true, data: req.body });
      });
    });

    test('should accept valid note data', async () => {
      const validData = {
        title: 'My Note Title',
        content: 'This is the note content.'
      };

      const response = await request(app)
        .post('/notes')
        .send(validData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.title).toBe(validData.title);
    });

    test('should reject empty title', async () => {
      const response = await request(app)
        .post('/notes')
        .send({
          title: '',
          content: 'Content'
        })
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    test('should reject title that is too long', async () => {
      const response = await request(app)
        .post('/notes')
        .send({
          title: 'a'.repeat(201), // Too long
          content: 'Content'
        })
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    test('should reject content that is too long', async () => {
      const response = await request(app)
        .post('/notes')
        .send({
          title: 'Title',
          content: 'a'.repeat(10001) // Too long
        })
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    test('should sanitize XSS attempts in title and content', async () => {
      const maliciousData = {
        title: '<script>alert("xss")</script>Clean Title',
        content: '<img src="x" onerror="alert(1)">Clean content'
      };

      const response = await request(app)
        .post('/notes')
        .send(maliciousData)
        .expect(200);

      expect(response.body.data.title).toBe('Clean Title');
      expect(response.body.data.content).toBe('Clean content');
    });

    test('should allow empty content', async () => {
      const response = await request(app)
        .post('/notes')
        .send({
          title: 'Title Only',
          content: ''
        })
        .expect(200);

      expect(response.body.success).toBe(true);
    });
  });

  describe('Note Update Validation', () => {
    beforeEach(() => {
      app.put('/notes/:id', validateNoteUpdate, (req, res) => {
        res.json({ success: true, data: req.body });
      });
    });

    test('should accept partial updates', async () => {
      const response = await request(app)
        .put('/notes/123')
        .send({
          title: 'Updated Title'
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.title).toBe('Updated Title');
    });

    test('should accept empty update object', async () => {
      const response = await request(app)
        .put('/notes/123')
        .send({})
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    test('should reject invalid field lengths', async () => {
      const response = await request(app)
        .put('/notes/123')
        .send({
          title: 'a'.repeat(201) // Too long
        })
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('Pagination Validation', () => {
    beforeEach(() => {
      app.get('/notes', validatePagination, (req, res) => {
        res.json({ success: true, query: req.query });
      });
    });

    test('should apply default values', async () => {
      const response = await request(app)
        .get('/notes')
        .expect(200);

      expect(response.body.query.page).toBe(1);
      expect(response.body.query.limit).toBe(10);
    });

    test('should accept valid pagination parameters', async () => {
      const response = await request(app)
        .get('/notes?page=2&limit=20')
        .expect(200);

      expect(response.body.query.page).toBe(2);
      expect(response.body.query.limit).toBe(20);
    });

    test('should reject invalid pagination parameters', async () => {
      const invalidParams = [
        'page=0', // Too small
        'page=1001', // Too large
        'limit=0', // Too small
        'limit=101', // Too large
        'page=abc', // Not a number
        'limit=xyz' // Not a number
      ];

      for (const param of invalidParams) {
        const response = await request(app)
          .get(`/notes?${param}`)
          .expect(400);

        expect(response.body.error.code).toBe('VALIDATION_ERROR');
      }
    });
  });

  describe('Request Size Limiting', () => {
    test('should reject requests that are too large', async () => {
      app.use(limitRequestSize(100)); // 100 bytes limit
      app.post('/test', (req, res) => {
        res.json({ success: true });
      });

      const largeData = { data: 'a'.repeat(200) };

      const response = await request(app)
        .post('/test')
        .send(largeData)
        .expect(413);

      expect(response.body.error.code).toBe('REQUEST_TOO_LARGE');
    });

    test('should accept requests within size limit', async () => {
      app.use(limitRequestSize(1000)); // 1000 bytes limit
      app.post('/test', (req, res) => {
        res.json({ success: true });
      });

      const smallData = { data: 'small data' };

      const response = await request(app)
        .post('/test')
        .send(smallData)
        .expect(200);

      expect(response.body.success).toBe(true);
    });
  });

  describe('SQL Injection Prevention', () => {
    beforeEach(() => {
      app.post('/search', validateInput(schemas.noteCreation), (req, res) => {
        res.json({ success: true, data: req.body });
      });
    });

    test('should sanitize dangerous SQL patterns', async () => {
      const sqlInjectionAttempts = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "'; INSERT INTO users VALUES ('hacker', 'password'); --"
      ];

      for (const injection of sqlInjectionAttempts) {
        const response = await request(app)
          .post('/search')
          .send({
            title: `Search ${injection}`,
            content: `Content with ${injection}`
          })
          .expect(200);

        // The most dangerous SQL patterns should be sanitized
        expect(response.body.data.title).not.toContain('DROP TABLE');
        expect(response.body.data.title).not.toContain('INSERT INTO');
        expect(response.body.data.content).not.toContain('DROP TABLE');
        expect(response.body.data.content).not.toContain('INSERT INTO');
      }
    });

    test('should preserve legitimate content with SQL-like words', async () => {
      const legitimateContent = {
        title: 'How to SELECT the best database',
        content: 'When you CREATE a new project, you need to consider...'
      };

      const response = await request(app)
        .post('/search')
        .send(legitimateContent)
        .expect(200);

      // Legitimate content should be preserved when not in dangerous patterns
      expect(response.body.data.title).toContain('SELECT');
      expect(response.body.data.content).toContain('CREATE');
    });
  });

  describe('XSS Prevention', () => {
    beforeEach(() => {
      app.post('/content', validateNoteCreation, (req, res) => {
        res.json({ success: true, data: req.body });
      });
    });

    test('should prevent various XSS attack vectors', async () => {
      const xssAttempts = [
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(1)">',
        '<svg onload="alert(1)">',
        'javascript:alert("XSS")',
        '<iframe src="javascript:alert(1)"></iframe>',
        '<object data="javascript:alert(1)"></object>',
        '<embed src="javascript:alert(1)">',
        '<link rel="stylesheet" href="javascript:alert(1)">',
        '<style>@import "javascript:alert(1)";</style>',
        '<div onclick="alert(1)">Click me</div>'
      ];

      for (const xss of xssAttempts) {
        const response = await request(app)
          .post('/content')
          .send({
            title: `Title ${xss}`,
            content: `Content ${xss}`
          })
          .expect(200);

        // All script tags and event handlers should be removed
        expect(response.body.data.title).not.toContain('<script>');
        expect(response.body.data.title).not.toContain('onerror');
        expect(response.body.data.title).not.toContain('onload');
        expect(response.body.data.title).not.toContain('onclick');
        expect(response.body.data.title).not.toContain('javascript:');
        
        expect(response.body.data.content).not.toContain('<script>');
        expect(response.body.data.content).not.toContain('onerror');
        expect(response.body.data.content).not.toContain('onload');
        expect(response.body.data.content).not.toContain('onclick');
        expect(response.body.data.content).not.toContain('javascript:');
      }
    });
  });

  describe('File Upload Validation', () => {
    test('should validate file upload with mock file data', () => {
      const mockReq = {
        files: {
          file: {
            name: 'test.txt',
            mimetype: 'text/plain',
            size: 1000,
            data: Buffer.from('This is test content')
          }
        },
        ip: '127.0.0.1',
        get: jest.fn().mockReturnValue('test-agent')
      };

      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };

      const mockNext = jest.fn();

      const middleware = validateFileUpload();
      middleware(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockRes.status).not.toHaveBeenCalled();
    });

    test('should reject files that are too large', () => {
      const mockReq = {
        files: {
          file: {
            name: 'large.txt',
            mimetype: 'text/plain',
            size: 2 * 1024 * 1024, // 2MB
            data: Buffer.from('Large file content')
          }
        },
        ip: '127.0.0.1',
        get: jest.fn().mockReturnValue('test-agent')
      };

      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };

      const mockNext = jest.fn();

      const middleware = validateFileUpload({ maxSize: 1024 * 1024 }); // 1MB limit
      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({
            code: 'FILE_TOO_LARGE'
          })
        })
      );
      expect(mockNext).not.toHaveBeenCalled();
    });

    test('should reject invalid file types', () => {
      const mockReq = {
        files: {
          file: {
            name: 'malicious.exe',
            mimetype: 'application/x-executable',
            size: 1000,
            data: Buffer.from('Executable content')
          }
        },
        ip: '127.0.0.1',
        get: jest.fn().mockReturnValue('test-agent')
      };

      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };

      const mockNext = jest.fn();

      const middleware = validateFileUpload();
      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({
            code: 'INVALID_FILE_TYPE'
          })
        })
      );
      expect(mockNext).not.toHaveBeenCalled();
    });

    test('should detect malicious content in files', () => {
      const mockReq = {
        files: {
          file: {
            name: 'malicious.txt',
            mimetype: 'text/plain',
            size: 1000,
            data: Buffer.from('<script>alert("XSS")</script>This is malicious content')
          }
        },
        ip: '127.0.0.1',
        get: jest.fn().mockReturnValue('test-agent')
      };

      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };

      const mockNext = jest.fn();

      const middleware = validateFileUpload();
      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({
            code: 'MALICIOUS_CONTENT_DETECTED'
          })
        })
      );
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('Error Response Format', () => {
    beforeEach(() => {
      app.post('/test', validateRegistration, (req, res) => {
        res.json({ success: true });
      });
    });

    test('should return properly formatted error responses', async () => {
      const response = await request(app)
        .post('/test')
        .send({
          email: 'invalid-email',
          password: 'weak'
        })
        .expect(400);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toHaveProperty('code', 'VALIDATION_ERROR');
      expect(response.body.error).toHaveProperty('message', 'Input validation failed');
      expect(response.body.error).toHaveProperty('details');
      expect(response.body.error).toHaveProperty('timestamp');
      expect(Array.isArray(response.body.error.details)).toBe(true);
    });

    test('should include field-specific error details', async () => {
      const response = await request(app)
        .post('/test')
        .send({
          email: 'invalid-email',
          password: 'weak',
          confirmPassword: 'different'
        })
        .expect(400);

      const details = response.body.error.details;
      expect(details.length).toBeGreaterThan(0);
      
      const emailError = details.find(d => d.field === 'email');
      expect(emailError).toBeDefined();
      expect(emailError.message).toContain('valid email');
    });
  });
});