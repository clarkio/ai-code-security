# Authentication System Documentation

## Table of Contents
- [Features](#features)
- [Environment Variables](#environment-variables)
- [Setup](#setup)
- [API Endpoints](#api-endpoints)
- [Rate Limiting](#rate-limiting)
- [Two-Factor Authentication (2FA)](#two-factor-authentication-2fa)
- [Session Management](#session-management)
- [Security Headers](#security-headers)

## Features

- **JWT Authentication** with access and refresh tokens
- **Rate Limiting** on authentication endpoints
- **Two-Factor Authentication** (2FA) with TOTP
- **Account Lockout** after multiple failed login attempts
- **Secure Password Reset** flow
- **Session Management** (view and revoke active sessions)
- **Role-Based Access Control** (RBAC)
- **Security Headers** for enhanced protection

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
# Server
NODE_ENV=development
PORT=3000

# Database
MONGODB_URI=mongodb://localhost:27017/secure-notes

# JWT
JWT_SECRET=your_jwt_secret_key
JWT_EXPIRES_IN=1d
JWT_COOKIE_EXPIRES_IN=1
JWT_REFRESH_SECRET=your_jwt_refresh_secret
JWT_REFRESH_EXPIRES_IN=7d
JWT_REFRESH_COOKIE_EXPIRES_IN=7

# Email (for password reset and notifications)
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USERNAME=your_email@example.com
EMAIL_PASSWORD=your_email_password
EMAIL_FROM=SecureNotes <noreply@example.com>

# App
APP_NAME=SecureNotes
APP_URL=http://localhost:3000
COOKIE_DOMAIN=localhost
```

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Set up environment variables (see above)

3. Start the development server:
   ```bash
   npm run dev
   ```

## API Endpoints

### Authentication

- `POST /api/v1/auth/signup` - Register a new user
- `POST /api/v1/auth/login` - Log in
- `POST /api/v1/auth/refresh-token` - Get new access token using refresh token
- `POST /api/v1/auth/logout` - Log out

### Password Management

- `POST /api/v1/auth/forgot-password` - Request password reset
- `POST /api/v1/auth/reset-password/:token` - Reset password
- `PATCH /api/v1/auth/update-password` - Update password (authenticated)

### 2FA (Two-Factor Authentication)

- `POST /api/v1/auth/2fa/setup` - Set up 2FA
- `POST /api/v1/auth/2fa/verify` - Verify 2FA token
- `POST /api/v1/auth/2fa/disable` - Disable 2FA
- `POST /api/v1/auth/2fa/verify-recovery` - Verify 2FA recovery code

### Session Management

- `GET /api/v1/auth/sessions` - Get active sessions
- `DELETE /api/v1/auth/sessions/:sessionId` - Revoke a session
- `DELETE /api/v1/auth/sessions` - Revoke all sessions

### User Management (Admin)

- `POST /api/v1/auth/users/:id/lock` - Lock user account
- `POST /api/v1/auth/users/:id/unlock` - Unlock user account

## Rate Limiting

Authentication endpoints are rate-limited to prevent brute force attacks:
- 10 requests per 15 minutes per IP for login/signup
- 5 requests per hour per account for sensitive operations

## Two-Factor Authentication (2FA)

### Enabling 2FA

1. Call `POST /api/v1/auth/2fa/setup` to generate a secret and get a QR code URL
2. Scan the QR code with an authenticator app (Google Authenticator, Authy, etc.)
3. Submit the generated code to `POST /api/v1/auth/2fa/verify`
4. Save the recovery codes in a secure place

### Recovering Access

If you lose access to your 2FA device:
1. Use one of your recovery codes at `POST /api/v1/auth/2fa/verify-recovery`
2. This will disable 2FA for your account
3. You'll need to set up 2FA again

## Session Management

### Viewing Active Sessions

- Call `GET /api/v1/auth/sessions` to see all active sessions
- Each session shows:
  - IP address
  - User agent
  - Last activity time
  - Current session indicator

### Revoking Sessions

- Revoke a specific session: `DELETE /api/v1/auth/sessions/:sessionId`
- Revoke all sessions (except current): `DELETE /api/v1/auth/sessions`

## Security Headers

The application includes the following security headers:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Content-Security-Policy` (restricts resources to same-origin)
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy` (disables geolocation, microphone, camera)

## Best Practices

1. Always use HTTPS in production
2. Store refresh tokens securely (HTTP-only cookies)
3. Implement proper CORS policies
4. Keep dependencies up to date
5. Monitor for suspicious activity
6. Regularly rotate secrets and keys
7. Use strong password policies
8. Implement account lockout after failed attempts
9. Use rate limiting on authentication endpoints
10. Keep audit logs of security-related events
