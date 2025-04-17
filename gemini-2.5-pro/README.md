# Secure Notes App

A simple, yet security-focused web application for creating, viewing, editing, and deleting notes, built with Node.js, Express, and MongoDB.

## Security Features Implemented

- **Helmet:** Sets various HTTP headers for security (CSP, XSS protection, etc.).
- **CSRF Protection:** Uses `csurf` middleware to prevent Cross-Site Request Forgery attacks on form submissions.
- **Input Validation:** Uses `express-validator` to validate and sanitize user input on the server-side.
- **Output Escaping:** EJS templates automatically escape output by default (`<%= ... %>`) to prevent XSS. Manual escaping (`<%- ... %>`) is used cautiously where needed.
- **Rate Limiting:** Basic IP-based rate limiting using `rate-limiter-flexible` to mitigate brute-force attacks.
- **Secure Session Management:** Uses `express-session` with `connect-mongo` for persistent sessions stored in MongoDB. Secure cookie flags (`httpOnly`, `secure` in production) are configured.
- **Environment Variables:** Sensitive configuration (database URI, session secret) is loaded from a `.env` file using `dotenv`, not hardcoded.
- **Error Handling:** Centralized error handling prevents leaking stack traces in production.
- **Mongoose Schema Validation:** Database-level validation for data integrity.

## Prerequisites

- Node.js (v14 or later recommended)
- npm (usually comes with Node.js)
- MongoDB (running locally or accessible via URI)

## Setup

1.  **Clone the repository (if applicable):**

    ```bash
    git clone <repository-url>
    cd secure-note-app
    ```

2.  **Install dependencies:**

    ```bash
    npm install
    ```

3.  **Create environment file:**
    - Copy the example environment file:
      ```bash
      cp .env.example .env
      ```
    - Edit the `.env` file and fill in the required values:
      - `MONGODB_URI`: Your MongoDB connection string (e.g., `mongodb://localhost:27017/secure-notes-app`).
      - `SESSION_SECRET`: A strong, random string for session encryption. You can generate one using Node's `crypto` module or an online generator.
      - `PORT` (Optional): Defaults to 3000.
      - `NODE_ENV`: Set to `production` for deployment, `development` otherwise.

## Running the Application

- **Development Mode (with automatic restart using nodemon):**

  ```bash
  npm run dev
  ```

  _Note: You might need to install nodemon globally (`npm install -g nodemon`) or adjust the script if it's only a dev dependency._

- **Production Mode:**
  ```bash
  npm start
  ```

Navigate to `http://localhost:PORT` (where `PORT` is the value in your `.env` file or 3000) in your web browser.

## Further Security Considerations (Production Deployment)

- **HTTPS:** ALWAYS deploy this application behind a reverse proxy (like Nginx or Apache) configured with HTTPS/TLS certificates (e.g., using Let's Encrypt).
- **Dependency Updates:** Regularly check for and apply updates to dependencies (`npm audit`, `npm update`).
- **Database Security:** Secure your MongoDB instance with authentication, authorization, and network restrictions.
- **Logging:** Configure more robust logging (e.g., using Winston) for production monitoring and auditing.
- **Security Audits:** Consider performing regular security audits or using vulnerability scanning tools.
- **Backup:** Implement regular backups of your database.
- **Principle of Least Privilege:** Ensure the Node.js process runs with the minimum necessary permissions on the server.
