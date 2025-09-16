# Security and Validation Middleware

This directory contains comprehensive security and validation middleware for the secure notes application.

## Components

### Validation Middleware (`validation.js`)

Provides input validation and sanitization using Joi schemas and DOMPurify:

- **Joi Schemas**: Pre-defined validation schemas for registration, login, notes, pagination, and file uploads
- **HTML Sanitization**: Removes XSS vectors while preserving legitimate content
- **SQL Injection Prevention**: Sanitizes dangerous SQL patterns
- **Request Size Limiting**: Prevents DoS attacks through large payloads
- **File Upload Validation**: Validates file types, sizes, and scans for malicious content

#### Usage Examples

```javascript
const { validateRegistration, validateNoteCreation, limitRequestSize } = require('./middleware');

// Apply validation to registration endpoint
app.post('/auth/register', validateRegistration, (req, res) => {
  // req.body is now validated and sanitized
});

// Apply note validation with request size limiting
app.post('/api/notes', 
  limitRequestSize(1024 * 1024), // 1MB limit
  validateNoteCreation, 
  (req, res) => {
    // Handle note creation
  }
);

// Custom validation
app.post('/api/search', 
  validateInput(schemas.noteCreation, 'body'),
  (req, res) => {
    // Handle search
  }
);
```

### Security Middleware (`security.js`)

Provides comprehensive security headers, rate limiting, CSRF protection, and logging:

- **Helmet Configuration**: Strict security headers (CSP, HSTS, X-Frame-Options, etc.)
- **Rate Limiting**: Configurable rate limits for different endpoint types
- **CSRF Protection**: Token-based CSRF protection for form submissions
- **CORS Configuration**: Restrictive CORS policies with origin validation
- **Security Logging**: Comprehensive logging of security events
- **Request Sanitization**: Removes null bytes and other dangerous characters

#### Usage Examples

```javascript
const { 
  helmetConfig, 
  authRateLimit, 
  apiRateLimit,
  csrfProtection,
  generateCsrfToken,
  securityLogger,
  corsConfig
} = require('./middleware/security');
const cors = require('cors');

// Apply security middleware globally
app.use(helmetConfig);
app.use(cors(corsConfig));
app.use(securityLogger);
app.use(generateCsrfToken);

// Apply rate limiting to specific routes
app.use('/auth', authRateLimit); // Strict rate limiting for auth
app.use('/api', apiRateLimit);   // General API rate limiting

// Apply CSRF protection to form endpoints
app.use('/forms', csrfProtection);
```

## Validation Schemas

### Registration Schema
- Email: Valid email format, max 254 characters
- Password: Min 12 chars, must contain uppercase, lowercase, number, special character
- Confirm Password: Must match password

### Login Schema
- Email: Valid email format
- Password: Required, max 128 characters

### Note Creation Schema
- Title: Required, 1-200 characters
- Content: Optional, max 10,000 characters

### Note Update Schema
- Title: Optional, 1-200 characters
- Content: Optional, max 10,000 characters

### Pagination Schema
- Page: Integer, min 1, max 1000, default 1
- Limit: Integer, min 1, max 100, default 10

### File Upload Schema
- Filename: Max 255 chars, alphanumeric with dots, dashes, underscores
- MIME Type: text/plain, text/markdown, application/json only
- Size: Max 1MB

## Security Features

### XSS Prevention
- Removes all HTML tags and attributes
- Sanitizes dangerous JavaScript protocols
- Preserves text content while removing markup

### SQL Injection Prevention
- Removes dangerous SQL keywords in injection contexts
- Preserves legitimate content with SQL-like words
- Note: Primary protection should come from parameterized queries

### Rate Limiting
- **Auth endpoints**: 5 requests per 15 minutes per IP
- **API endpoints**: 100 requests per 15 minutes per IP
- **Upload endpoints**: 10 requests per hour per IP

### CSRF Protection
- Token-based protection for non-GET requests
- Automatic token generation and validation
- Skips protection for JWT-authenticated API endpoints

### Security Headers
- Content Security Policy (CSP)
- HTTP Strict Transport Security (HSTS)
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer Policy: strict-origin-when-cross-origin

## Error Handling

All middleware components return consistent error responses:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable message",
    "details": [...], // For validation errors
    "timestamp": "2024-01-01T00:00:00Z"
  }
}
```

### Error Codes
- `VALIDATION_ERROR`: Input validation failed
- `REQUEST_TOO_LARGE`: Request exceeds size limit
- `RATE_LIMIT_EXCEEDED`: Too many requests
- `CSRF_TOKEN_INVALID`: Invalid or missing CSRF token
- `FILE_TOO_LARGE`: File exceeds size limit
- `INVALID_FILE_TYPE`: File type not allowed
- `MALICIOUS_CONTENT_DETECTED`: File contains dangerous content

## Testing

Comprehensive test suites are provided for both validation and security middleware:

```bash
# Run all middleware tests
npm test src/middleware/

# Run specific test files
npm test src/middleware/validation.test.js
npm test src/middleware/security.test.js
```

The tests cover:
- Input validation and sanitization
- XSS prevention
- SQL injection prevention
- Rate limiting
- CSRF protection
- File upload validation
- Error response formatting
- Security header configuration

## Integration with Application

To integrate these middleware components into your Express application:

1. **Global Security Setup**:
```javascript
const express = require('express');
const { helmetConfig, securityLogger, corsConfig } = require('./middleware/security');
const cors = require('cors');

const app = express();

// Apply global security middleware
app.use(helmetConfig);
app.use(cors(corsConfig));
app.use(securityLogger);
app.use(express.json({ limit: '1mb' }));
```

2. **Route-Specific Validation**:
```javascript
const { 
  validateRegistration, 
  validateLogin, 
  validateNoteCreation,
  authRateLimit 
} = require('./middleware');

// Authentication routes with rate limiting and validation
app.post('/auth/register', authRateLimit, validateRegistration, authController.register);
app.post('/auth/login', authRateLimit, validateLogin, authController.login);

// Note routes with validation
app.post('/api/notes', validateNoteCreation, notesController.create);
app.put('/api/notes/:id', validateNoteUpdate, notesController.update);
```

3. **File Upload Routes**:
```javascript
const { validateFileUpload, uploadRateLimit } = require('./middleware');

app.post('/api/upload', 
  uploadRateLimit,
  validateFileUpload({ maxSize: 5 * 1024 * 1024 }), // 5MB
  uploadController.handleUpload
);
```

This middleware provides defense-in-depth security for your application, protecting against common web vulnerabilities while maintaining usability and performance.