# Secure Notes Application

A production-ready, security-focused Node.js notes application.

## Security Features

- **Helmet.js** - Security headers (HSTS, CSP, X-Frame-Options, etc.)
- **bcrypt** - Password hashing with 12 rounds
- **JWT** - Access and refresh token authentication
- **Rate Limiting** - Prevents brute force and DoS attacks
- **Input Validation** - express-validator on all inputs
- **XSS Protection** - DOMPurify sanitization
- **SQL Injection Prevention** - Parameterized queries
- **Account Lockout** - After 5 failed login attempts
- **Token Rotation** - Refresh tokens are revoked after use

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Copy environment template
cp .env.example .env

# 3. Edit .env with secure values
#    - Generate strong secrets (32+ characters)
#    - Set NODE_ENV=production for deployment

# 4. Start the server
npm start
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PORT` | Server port (default: 3000) |
| `NODE_ENV` | Set to `production` for deployment |
| `JWT_SECRET` | Access token secret (min 32 chars) |
| `JWT_REFRESH_SECRET` | Refresh token secret (min 32 chars) |
| `SESSION_SECRET` | Session secret (min 32 chars) |
| `RATE_LIMIT_MAX_REQUESTS` | Requests per window (default: 100) |
| `ALLOWED_ORIGINS` | CORS origins (comma-separated) |

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login (returns tokens)
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - Revoke refresh token

### Notes
- `GET /api/notes` - List user's notes (paginated)
- `GET /api/notes/:id` - Get single note
- `POST /api/notes` - Create note
- `PUT /api/notes/:id` - Update note
- `DELETE /api/notes/:id` - Delete note

## Production Deployment

1. Set `NODE_ENV=production`
2. Use strong, unique secrets for all JWT/Session keys
3. Configure reverse proxy (nginx/Apache)
4. Enable HTTPS (required for HSTS)
5. Set up proper logging/monitoring
6. Regular backups of the SQLite database

## Project Structure

```
minimax-m2.1/
├── src/
│   ├── config/environment.js   # Config loader
│   ├── database/init.js        # SQLite setup
│   ├── lib/
│   │   ├── auth.js             # Auth logic
│   │   └── sanitizer.js        # XSS protection
│   ├── middleware/
│   │   ├── auth.js             # JWT verification
│   │   ├── security.js         # Helmet, rate limiting
│   │   └── validation.js       # Input validation
│   ├── routes/
│   │   ├── auth.js             # Auth endpoints
│   │   └── notes.js            # Notes CRUD
│   └── server.js               # Express app
├── public/
│   ├── index.html              # SPA frontend
│   ├── styles.css
│   └── app.js
├── .env.example                # Environment template
└── package.json
```
