# Design Document

## Overview

The secure notes application will be built as a Node.js web application using Express.js framework with a layered architecture emphasizing security at every level. The application implements defense-in-depth security principles with multiple layers of protection including authentication, authorization, input validation, output encoding, and comprehensive logging.

The architecture follows the principle of least privilege, secure by default configuration, and fail-safe defaults. All security measures are implemented proactively rather than reactively.

## Architecture

### High-Level Architecture

```mermaid
graph TB
    Client[Web Browser] --> LB[Load Balancer/Reverse Proxy]
    LB --> App[Node.js Application]
    App --> DB[(PostgreSQL Database)]
    App --> Redis[(Redis Session Store)]
    App --> Logger[Winston Logger]
    
    subgraph "Security Layers"
        WAF[Web Application Firewall]
        TLS[TLS/HTTPS Termination]
        RateLimit[Rate Limiting]
        Auth[JWT Authentication]
        RBAC[Authorization Layer]
        Validation[Input Validation]
        Encryption[Data Encryption]
    end
```

### Technology Stack

- **Runtime**: Node.js 18+ LTS
- **Framework**: Express.js with security middleware
- **Database**: PostgreSQL with encrypted connections
- **Session Store**: Redis for session management
- **Authentication**: JWT with refresh tokens
- **Encryption**: Node.js crypto module (AES-256-GCM)
- **Password Hashing**: bcrypt with cost factor 12
- **Logging**: Winston with structured logging
- **Testing**: Jest with security-focused test cases

## Components and Interfaces

### 1. Authentication Service

**Purpose**: Handles user registration, login, and token management

**Key Security Features**:
- Password complexity validation
- bcrypt hashing with salt rounds 12
- JWT token generation with short expiration
- Refresh token rotation
- Account lockout after failed attempts
- Rate limiting per IP and per user

**Interface**:
```javascript
class AuthService {
  async register(email, password, confirmPassword)
  async login(email, password, ipAddress)
  async refreshToken(refreshToken)
  async logout(userId, tokenId)
  async validateToken(token)
}
```

### 2. Notes Service

**Purpose**: Manages CRUD operations for user notes with authorization

**Key Security Features**:
- User ownership validation for all operations
- Input sanitization and validation
- Content length limits
- Encrypted storage of note content
- Audit logging of all operations

**Interface**:
```javascript
class NotesService {
  async createNote(userId, title, content)
  async getNotes(userId, pagination)
  async getNote(userId, noteId)
  async updateNote(userId, noteId, title, content)
  async deleteNote(userId, noteId)
}
```

### 3. Encryption Service

**Purpose**: Handles encryption/decryption of sensitive data

**Key Security Features**:
- AES-256-GCM encryption
- Unique IV for each encryption operation
- Secure key management from environment variables
- Key rotation capability

**Interface**:
```javascript
class EncryptionService {
  encrypt(plaintext)
  decrypt(encryptedData)
  generateKey()
  rotateKeys()
}
```

### 4. Validation Middleware

**Purpose**: Validates and sanitizes all user input

**Key Security Features**:
- Schema-based validation using Joi
- HTML sanitization to prevent XSS
- SQL injection prevention through parameterized queries
- File upload validation and scanning

**Interface**:
```javascript
class ValidationMiddleware {
  validateRegistration(req, res, next)
  validateLogin(req, res, next)
  validateNoteCreation(req, res, next)
  validateNoteUpdate(req, res, next)
  sanitizeInput(input)
}
```

### 5. Security Middleware

**Purpose**: Implements various security headers and protections

**Key Security Features**:
- Helmet.js for security headers
- CORS configuration
- CSRF protection
- Rate limiting
- Request size limits

## Data Models

### User Model

```javascript
{
  id: UUID (Primary Key),
  email: String (Unique, Encrypted),
  passwordHash: String (bcrypt),
  isActive: Boolean,
  failedLoginAttempts: Integer,
  lastFailedLogin: Timestamp,
  accountLockedUntil: Timestamp,
  createdAt: Timestamp,
  updatedAt: Timestamp,
  lastLoginAt: Timestamp
}
```

### Note Model

```javascript
{
  id: UUID (Primary Key),
  userId: UUID (Foreign Key, Indexed),
  title: String (Encrypted),
  content: Text (Encrypted),
  encryptionIV: String,
  createdAt: Timestamp,
  updatedAt: Timestamp,
  isDeleted: Boolean (Soft Delete)
}
```

### Session Model (Redis)

```javascript
{
  sessionId: String (Key),
  userId: UUID,
  tokenId: UUID,
  ipAddress: String,
  userAgent: String,
  createdAt: Timestamp,
  expiresAt: Timestamp,
  isActive: Boolean
}
```

### Audit Log Model

```javascript
{
  id: UUID (Primary Key),
  userId: UUID,
  action: String,
  resource: String,
  resourceId: UUID,
  ipAddress: String,
  userAgent: String,
  success: Boolean,
  errorMessage: String,
  timestamp: Timestamp
}
```

## Error Handling

### Security-First Error Handling Strategy

1. **Information Disclosure Prevention**:
   - Generic error messages for authentication failures
   - No stack traces in production responses
   - Detailed logging for debugging without user exposure

2. **Error Categories**:
   - Authentication errors (401)
   - Authorization errors (403)
   - Validation errors (400)
   - Rate limiting errors (429)
   - Server errors (500)

3. **Error Response Format**:
```javascript
{
  error: {
    code: "AUTH_FAILED",
    message: "Authentication failed",
    timestamp: "2024-01-01T00:00:00Z",
    requestId: "uuid"
  }
}
```

### Global Error Handler

```javascript
class SecurityErrorHandler {
  handleAuthenticationError(error, req, res, next)
  handleValidationError(error, req, res, next)
  handleAuthorizationError(error, req, res, next)
  handleRateLimitError(error, req, res, next)
  handleGenericError(error, req, res, next)
  logSecurityEvent(error, req)
}
```

## Testing Strategy

### Security Testing Approach

1. **Unit Tests**:
   - Authentication service security functions
   - Encryption/decryption operations
   - Input validation and sanitization
   - Authorization checks

2. **Integration Tests**:
   - End-to-end authentication flows
   - CRUD operations with authorization
   - Security middleware functionality
   - Database security (encrypted connections)

3. **Security Tests**:
   - SQL injection prevention
   - XSS prevention
   - CSRF protection
   - Rate limiting effectiveness
   - Authentication bypass attempts
   - Authorization bypass attempts

4. **Penetration Testing Checklist**:
   - OWASP Top 10 vulnerability testing
   - Authentication and session management
   - Input validation and output encoding
   - Error handling and information disclosure
   - Cryptographic implementation

### Test Security Data

- Use test-specific encryption keys
- Mock external services securely
- Sanitize test data in logs
- Separate test and production databases
- Automated security scanning in CI/CD

## Security Configuration

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/notes_db
DATABASE_SSL=true

# Encryption
ENCRYPTION_KEY=base64-encoded-256-bit-key
ENCRYPTION_KEY_ROTATION=base64-encoded-256-bit-key

# JWT
JWT_SECRET=base64-encoded-secret
JWT_REFRESH_SECRET=base64-encoded-refresh-secret
JWT_EXPIRY=15m
JWT_REFRESH_EXPIRY=7d

# Redis
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=secure-password

# Security
BCRYPT_ROUNDS=12
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX_REQUESTS=5
SESSION_TIMEOUT=15

# Application
NODE_ENV=production
PORT=3000
CORS_ORIGIN=https://yourdomain.com
```

### Security Headers Configuration

```javascript
const securityHeaders = {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}
```

## Deployment Security

### Production Checklist

1. **Server Security**:
   - Regular security updates
   - Firewall configuration
   - Intrusion detection system
   - Log monitoring and alerting

2. **Application Security**:
   - Environment variable security
   - Secrets management
   - Database connection encryption
   - Regular dependency updates

3. **Monitoring and Alerting**:
   - Failed authentication attempts
   - Unusual access patterns
   - Error rate monitoring
   - Performance monitoring

This design provides a comprehensive security-first approach to building your notes application, ensuring protection against common vulnerabilities while maintaining usability and performance.