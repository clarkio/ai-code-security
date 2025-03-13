# Secure Notes Application

A production-ready, secure note-taking application built with Node.js, Express, MongoDB, and modern security practices.

## Features

- User authentication with secure password hashing
- Create, read, update, and delete notes
- Full CSRF protection
- Rate limiting to prevent brute force attacks
- Secure HTTP headers with Helmet
- Data validation and sanitization
- Account lockout after failed login attempts
- Session management with secure cookies
- MongoDB for data persistence
- Responsive user interface

## Security Features

This application implements numerous security best practices:

1. **Authentication Security**
   - Password hashing with bcrypt
   - Account lockout after 5 failed attempts
   - Strong password requirements
   - Input validation and sanitization

2. **Data Protection**
   - CSRF protection on all state-changing operations
   - MongoDB document access control
   - Input validation and sanitization
   - XSS protection with content security policy

3. **Infrastructure Security**
   - Rate limiting on authentication endpoints
   - API rate limiting
   - Secure HTTP headers with Helmet
   - Secure cookie settings (HttpOnly, Secure, SameSite)
   - Proper error handling without information leakage

4. **Code Security**
   - Environment configuration validation
   - Proper MongoDB connection handling
   - Secure session management
   - Thorough input validation

## Prerequisites

- Node.js (v18 or higher)
- MongoDB (local instance or MongoDB Atlas)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/secure-notes-app.git
   cd secure-notes-app
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Create a `.env` file in the root directory (copy from `.env.example`):
   ```
   NODE_ENV=development
   PORT=3000
   MONGODB_URI=mongodb://localhost:27017/secure-notes
   SESSION_SECRET=your_strong_random_secret_here
   RATE_LIMIT_WINDOW_MS=900000
   RATE_LIMIT_MAX=100
   ```
   
   **Important:** For production, generate a strong random string for SESSION_SECRET.

4. Start the application:
   ```
   npm start
   ```
   
   For development with auto-reload:
   ```
   npm run dev
   ```

5. Access the application at `http://localhost:3000`

## Deployment Considerations

When deploying to production:

1. Set `NODE_ENV=production` in your environment
2. Use a strong, unique SESSION_SECRET
3. Consider using a production-ready MongoDB instance
4. Set up proper logging
5. Configure a reverse proxy like Nginx with HTTPS
6. Implement proper backup strategies
7. Set up monitoring and alerting

## License

MIT