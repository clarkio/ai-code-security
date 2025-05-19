# Secure Notes App

A secure, production-ready Node.js application for creating, updating, and deleting notes with robust security features.

## Features

- **User Authentication**: Secure signup and login with JWT
- **Note Management**: Create, read, update, and delete notes
- **Security**:
  - Password hashing with bcrypt
  - Rate limiting
  - Helmet for secure HTTP headers
  - Data sanitization
  - XSS protection
  - CSRF protection
  - Secure HTTP headers
  - Input validation
  - Account lockout after failed attempts
- **Search**: Full-text search across notes
- **Pagination**: For better performance with large numbers of notes
- **Tags**: Organize notes with tags
- **Responsive Design**: Works on desktop and mobile

## Prerequisites

- Node.js (v14 or later)
- MongoDB (v4.4 or later)
- npm (v6 or later)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/secure-notes-app.git
   cd secure-notes-app
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a `.env` file in the root directory with the following variables:
   ```
   NODE_ENV=development
   PORT=3000
   MONGODB_URI=mongodb://localhost:27017/secure_notes
   JWT_SECRET=your_jwt_secret_key_here
   JWT_EXPIRES_IN=90d
   JWT_COOKIE_EXPIRES_IN=90
   EMAIL_FROM=your-email@example.com
   EMAIL_HOST=smtp.mailtrap.io
   EMAIL_PORT=2525
   EMAIL_USERNAME=your-email-username
   EMAIL_PASSWORD=your-email-password
   ```

4. Start the development server:
   ```bash
   npm run dev
   ```

## Available Scripts

- `npm start`: Start the production server
- `npm run dev`: Start the development server with nodemon
- `npm test`: Run tests
- `npm run lint`: Lint the codebase
- `npm run format`: Format the codebase with Prettier

## API Documentation

### Authentication

- `POST /api/v1/auth/signup` - Register a new user
- `POST /api/v1/auth/login` - Login user
- `GET /api/v1/auth/logout` - Logout user
- `POST /api/v1/auth/forgotPassword` - Request password reset
- `PATCH /api/v1/auth/resetPassword/:token` - Reset password
- `PATCH /api/v1/auth/updateMyPassword` - Update password (requires authentication)

### Notes

- `GET /api/v1/notes` - Get all notes (paginated)
- `POST /api/v1/notes` - Create a new note
- `GET /api/v1/notes/:id` - Get a specific note
- `PATCH /api/v1/notes/:id` - Update a note
- `DELETE /api/v1/notes/:id` - Delete a note
- `GET /api/v1/notes/search?q=query` - Search notes
- `GET /api/v1/notes/stats` - Get note statistics

## Security Best Practices

1. **Authentication**:
   - Uses JWT with HTTP-only cookies
   - Password hashing with bcrypt
   - Account lockout after multiple failed login attempts

2. **Data Protection**:
   - Input validation and sanitization
   - Protection against NoSQL injection
   - XSS protection
   - Rate limiting

3. **Secure Headers**:
   - Helmet for setting various HTTP headers
   - CORS configuration
   - Content Security Policy

4. **Error Handling**:
   - Custom error handling middleware
   - No stack traces in production
   - Proper HTTP status codes

## Environment Variables

- `NODE_ENV`: Application environment (development, production)
- `PORT`: Port to run the server on
- `MONGODB_URI`: MongoDB connection string
- `JWT_SECRET`: Secret for signing JWTs
- `JWT_EXPIRES_IN`: JWT expiration time (e.g., 90d)
- `JWT_COOKIE_EXPIRES_IN`: JWT cookie expiration in days
- `EMAIL_*`: Email configuration for sending password resets

## Testing

To run tests:

```bash
npm test
```

## Deployment

1. Set `NODE_ENV` to `production`
2. Update the `MONGODB_URI` to your production database
3. Set a strong `JWT_SECRET`
4. Configure your production email service
5. Deploy to your preferred hosting provider (e.g., Heroku, AWS, etc.)

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
