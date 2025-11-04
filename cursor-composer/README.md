# Secure Notes Application

A production-ready, secure Node.js web application for managing notes with comprehensive security features.

## Security Features

✅ **Authentication & Authorization**
- JWT-based authentication with secure token expiration
- Bcrypt password hashing (12 salt rounds)
- Strong password requirements (min 8 chars, uppercase, lowercase, number)

✅ **SQL Injection Prevention**
- All database queries use parameterized queries (prepared statements)
- No string concatenation in SQL queries

✅ **XSS Prevention**
- Input sanitization and validation
- HTML escaping in frontend
- Content Security Policy headers

✅ **CSRF Protection**
- SameSite cookies
- Session-based CSRF token storage

✅ **Security Headers**
- Helmet.js for secure HTTP headers
- Content Security Policy
- X-Frame-Options, X-Content-Type-Options, etc.

✅ **Rate Limiting**
- General API rate limiting (100 requests per 15 minutes)
- Strict authentication rate limiting (5 attempts per 15 minutes)

✅ **Input Validation**
- Express-validator for all user inputs
- Email normalization
- Length limits and format validation

✅ **Error Handling**
- No sensitive information leakage in error messages
- Proper error logging without exposing internals

✅ **Other Security Measures**
- HTTP Parameter Pollution prevention
- Secure session cookies (httpOnly, secure in production)
- CORS configuration
- Payload size limits
- Database connection pooling with timeouts

## Prerequisites

- Node.js 18+ 
- PostgreSQL 12+
- npm or yarn

## Installation

1. Clone the repository
```bash
git clone <repository-url>
cd cursor-composer
```

2. Install dependencies
```bash
npm install
```

3. Set up PostgreSQL database
```bash
createdb notesdb
```

4. Configure environment variables
```bash
cp .env.example .env
```

Edit `.env` and set:
- `DATABASE_URL` - Your PostgreSQL connection string
- `JWT_SECRET` - Generate a random secret: `openssl rand -base64 32`
- `SESSION_SECRET` - Generate a random secret: `openssl rand -base64 32`
- `NODE_ENV` - Set to `production` for production deployment
- `FRONTEND_URL` - Your frontend URL for CORS

5. Start the server
```bash
npm start
```

For development with auto-reload:
```bash
npm run dev
```

## API Endpoints

### Authentication

**POST /api/auth/register**
- Register a new user
- Body: `{ username, email, password }`
- Returns: JWT token and user info

**POST /api/auth/login**
- Login user
- Body: `{ email, password }`
- Returns: JWT token and user info

### Notes (Requires Authentication)

**GET /api/notes**
- Get all notes for authenticated user
- Headers: `Authorization: Bearer <token>`

**GET /api/notes/:id**
- Get single note by ID
- Headers: `Authorization: Bearer <token>`

**POST /api/notes**
- Create new note
- Headers: `Authorization: Bearer <token>`
- Body: `{ title, content }`

**PUT /api/notes/:id**
- Update existing note
- Headers: `Authorization: Bearer <token>`
- Body: `{ title, content }`

**DELETE /api/notes/:id**
- Delete note
- Headers: `Authorization: Bearer <token>`

## Production Deployment Checklist

- [ ] Change `JWT_SECRET` to a strong random value
- [ ] Change `SESSION_SECRET` to a strong random value
- [ ] Set `NODE_ENV=production`
- [ ] Use HTTPS (set `secure: true` in session config)
- [ ] Use a production-grade PostgreSQL database
- [ ] Set up proper firewall rules
- [ ] Configure reverse proxy (nginx/Apache) if needed
- [ ] Set up monitoring and logging
- [ ] Regular security updates for dependencies
- [ ] Set up database backups
- [ ] Review and configure CORS properly
- [ ] Set up rate limiting at infrastructure level (e.g., Cloudflare)

## Security Best Practices Applied

1. **Never trust user input** - All inputs are validated and sanitized
2. **Use parameterized queries** - Prevents SQL injection
3. **Hash passwords** - Never store plaintext passwords
4. **Secure sessions** - httpOnly, secure cookies
5. **Rate limiting** - Prevents brute force attacks
6. **Error handling** - No information leakage
7. **Security headers** - Helmet.js configuration
8. **CORS** - Properly configured
9. **Input limits** - Prevents DoS via large payloads
10. **Token expiration** - JWT tokens expire after 24 hours

## Testing

Run tests (when implemented):
```bash
npm test
```

## License

ISC

