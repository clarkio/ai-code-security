# Secure Notes App (google-jules)

## Overview

`google-jules` is a secure Node.js application designed to provide a robust API for creating, reading, updating, and deleting notes. It emphasizes security best practices, including JWT-based authentication, CSRF protection, input validation, and secure header configurations. The application serves as a backend API, which can be consumed by any frontend client (e.g., a Single Page Application). A simple example frontend is provided in the `public` directory.

## Features

*   **User Authentication:**
    *   User registration with password hashing (bcryptjs).
    *   User login with JWT (JSON Web Token) generation.
*   **Note Management (CRUD):**
    *   Create, Read, Update, and Delete notes.
    *   Notes are user-specific; users can only access their own notes.
*   **Security:**
    *   JWT-based authorization for protected routes.
    *   CSRF (Cross-Site Request Forgery) protection on state-changing endpoints.
    *   Secure HTTP headers set by `helmet`.
    *   Rate limiting on API and authentication routes.
    *   Input validation for all incoming data using `express-validator`.
    *   Parameterized queries to prevent SQL injection.
    *   CORS (Cross-Origin Resource Sharing) configuration.
*   **Database:**
    *   Uses SQLite for ease of setup and development.
    *   Schema includes `users` and `notes` tables.
*   **Logging:**
    *   Comprehensive logging using `winston` and `morgan`.
*   **Testing:**
    *   Integration tests using Jest and Supertest.

## Tech Stack

*   **Backend:** Node.js, Express.js
*   **Database:** SQLite
*   **Authentication:** bcryptjs (password hashing), jsonwebtoken (JWT)
*   **Security Middleware:** helmet (security headers), express-rate-limit (rate limiting), csurf (CSRF protection), cors (CORS)
*   **Validation:** express-validator
*   **Logging:** winston, morgan
*   **Development:** nodemon (auto-restarting server)
*   **Testing:** Jest, Supertest

## Prerequisites

*   Node.js (v14.x or later recommended)
*   npm (Node Package Manager, usually comes with Node.js)

## Setup and Installation

1.  **Clone the repository (if you haven't already):**
    ```bash
    git clone <repository-url>
    cd google-jules
    ```

2.  **Navigate to the project directory:**
    ```bash
    cd google-jules
    ```

3.  **Install dependencies:**
    ```bash
    npm install
    ```

4.  **Set up environment variables:**
    *   Copy the example environment file:
        ```bash
        cp .env.example .env
        ```
    *   Open the `.env` file and customize the variables as needed. Key variables include:
        *   `NODE_ENV`: Set to `development` for local development, `production` for deployment.
        *   `PORT`: The port the application will run on (e.g., `3000`).
        *   `JWT_SECRET`: **Crucial for security.** A strong, random string used to sign JWTs. **Generate a unique one for production.**
            *   Example generation: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
        *   `CSRF_SECRET`: **Important for CSRF protection.** A strong, random string used to sign CSRF tokens. **Generate a unique one for production.**
            *   Example generation: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
        *   `DATABASE_URL`: Path to the SQLite database file (e.g., `./notes.sqlite`). For production, consider a more robust database.
        *   `CORS_ORIGIN`: The URL of your frontend application (e.g., `http://localhost:3001` or your production frontend domain).
        *   `LOG_LEVEL`: Logging level (e.g., `info`, `debug`, `error`).

5.  **Initialize the database:**
    This command creates the necessary tables (`users`, `notes`) in your SQLite database.
    ```bash
    npm run db:setup
    ```

## Running the Application

*   **Development Mode (with auto-reload using `nodemon`):**
    ```bash
    npm run dev
    ```
    The server will typically start on `http://localhost:3000` (or the `PORT` specified in your `.env`).

*   **Production Mode:**
    ```bash
    npm start
    ```
    For production deployments, it is highly recommended to use a process manager like PM2 or systemd to manage the application lifecycle.

## API Endpoints

All API endpoints are prefixed with `/api`. Protected routes require a JWT in the `Authorization: Bearer <token>` header. State-changing operations (POST, PUT, DELETE) on protected resources also require an `X-CSRF-Token` header.

### Authentication

*   `POST /api/auth/register`
    *   Description: Register a new user.
    *   Body: `{ "username": "yourusername", "email": "user@example.com", "password": "yourpassword" }`
*   `POST /api/auth/login`
    *   Description: Login an existing user.
    *   Body: `{ "email": "user@example.com", "password": "yourpassword" }`
    *   Returns: JWT token.
*   `GET /api/auth/csrf-token`
    *   Description: Get a CSRF token. This token should be included in the `X-CSRF-Token` header for subsequent state-changing requests.

### Notes (Protected Routes)

*   `POST /api/notes`
    *   Description: Create a new note.
    *   Body: `{ "title": "Note Title", "content": "Note content" }`
*   `GET /api/notes`
    *   Description: Get all notes for the authenticated user.
*   `GET /api/notes/:id`
    *   Description: Get a specific note by its ID.
*   `PUT /api/notes/:id`
    *   Description: Update an existing note by its ID.
    *   Body: `{ "title": "Updated Title", "content": "Updated content" }`
*   `DELETE /api/notes/:id`
    *   Description: Delete a note by its ID.

## Testing

Run the integration tests using Jest and Supertest:
```bash
npm test
```
Tests are configured to run with an in-memory SQLite database and specific test environment settings.

## Project Structure

```
google-jules/
├── config/             # Configuration files (database, JWT, logger)
├── controllers/        # Request handlers and business logic
├── middleware/         # Custom Express middleware (e.g., auth)
├── models/             # Database interaction logic (data models)
├── public/             # Static frontend files (HTML, CSS, JS client)
├── routes/             # Express route definitions
├── tests/              # Automated tests (Jest/Supertest)
├── .env.example        # Example environment variables
├── .gitignore          # Files/directories to ignore in Git
├── app.js              # Main Express application setup
├── database-setup.js   # Script to initialize database schema
├── package.json        # Project metadata and dependencies
└── README.md           # This file
```

See `SECURITY.md` for important security information regarding this application.
