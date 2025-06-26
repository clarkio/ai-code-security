const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const database = require('./database');

class AuthService {
    constructor() {
        this.JWT_SECRET = process.env.JWT_SECRET;
        this.JWT_EXPIRES_IN = '1h';
        this.MAX_FAILED_ATTEMPTS = 5;
        this.LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

        if (!this.JWT_SECRET || this.JWT_SECRET.length < 32) {
            console.error('JWT_SECRET must be at least 32 characters long');
            process.exit(1);
        }
    }

    // Generate secure password hash
    async hashPassword(password) {
        const saltRounds = 12;
        return await bcrypt.hash(password, saltRounds);
    }

    // Verify password against hash
    async verifyPassword(password, hash) {
        return await bcrypt.compare(password, hash);
    }

    // Generate JWT token with additional security claims
    generateToken(user) {
        const jti = crypto.randomUUID(); // JWT ID for blacklisting
        const payload = {
            id: user.id,
            username: user.username,
            email: user.email,
            jti: jti,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour
        };

        return jwt.sign(payload, this.JWT_SECRET);
    }

    // Verify and decode JWT token
    async verifyToken(token) {
        try {
            const decoded = jwt.verify(token, this.JWT_SECRET);
            
            // Check if token is blacklisted
            const blacklistedToken = await database.get(
                'SELECT token_jti FROM session_blacklist WHERE token_jti = ?',
                [decoded.jti]
            );

            if (blacklistedToken) {
                throw new Error('Token has been invalidated');
            }

            return decoded;
        } catch (error) {
            throw new Error('Invalid or expired token');
        }
    }

    // Blacklist token (for logout)
    async blacklistToken(token) {
        try {
            const decoded = jwt.decode(token);
            if (decoded && decoded.jti && decoded.exp) {
                const expiresAt = new Date(decoded.exp * 1000);
                await database.run(
                    'INSERT OR IGNORE INTO session_blacklist (token_jti, expires_at) VALUES (?, ?)',
                    [decoded.jti, expiresAt.toISOString()]
                );
            }
        } catch (error) {
            console.error('Error blacklisting token:', error);
        }
    }

    // Check if account is locked
    async isAccountLocked(user) {
        if (user.locked_until) {
            const lockoutTime = new Date(user.locked_until);
            if (lockoutTime > new Date()) {
                return true;
            } else {
                // Reset failed attempts if lockout period has passed
                await database.run(
                    'UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?',
                    [user.id]
                );
            }
        }
        return false;
    }

    // Handle failed login attempt
    async handleFailedLogin(userId) {
        const user = await database.get('SELECT failed_login_attempts FROM users WHERE id = ?', [userId]);
        const failedAttempts = (user.failed_login_attempts || 0) + 1;
        
        let lockedUntil = null;
        if (failedAttempts >= this.MAX_FAILED_ATTEMPTS) {
            lockedUntil = new Date(Date.now() + this.LOCKOUT_TIME).toISOString();
        }

        await database.run(
            'UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?',
            [failedAttempts, lockedUntil, userId]
        );
    }

    // Reset failed login attempts on successful login
    async resetFailedAttempts(userId) {
        await database.run(
            'UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?',
            [userId]
        );
    }

    // Register new user
    async register(username, email, password) {
        // Validate input
        if (!username || username.length < 3 || username.length > 50) {
            throw new Error('Username must be between 3 and 50 characters');
        }

        if (!email || !email.includes('@') || !email.includes('.')) {
            throw new Error('Invalid email format');
        }

        if (!password || password.length < 8) {
            throw new Error('Password must be at least 8 characters long');
        }

        // Check for password complexity
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        if (!(hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar)) {
            throw new Error('Password must contain uppercase, lowercase, numbers, and special characters');
        }

        // Check if user already exists
        const existingUser = await database.get(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            [username, email]
        );

        if (existingUser) {
            throw new Error('Username or email already exists');
        }

        // Hash password and create user
        const passwordHash = await this.hashPassword(password);
        const result = await database.run(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            [username, email, passwordHash]
        );

        return { id: result.id, username, email };
    }

    // Login user
    async login(usernameOrEmail, password) {
        // Find user by username or email
        const user = await database.get(
            'SELECT * FROM users WHERE (username = ? OR email = ?) AND is_active = 1',
            [usernameOrEmail, usernameOrEmail]
        );

        if (!user) {
            throw new Error('Invalid credentials');
        }

        // Check if account is locked
        if (await this.isAccountLocked(user)) {
            throw new Error('Account temporarily locked due to too many failed attempts');
        }

        // Verify password
        const isValidPassword = await this.verifyPassword(password, user.password_hash);
        
        if (!isValidPassword) {
            await this.handleFailedLogin(user.id);
            throw new Error('Invalid credentials');
        }

        // Reset failed attempts on successful login
        await this.resetFailedAttempts(user.id);

        // Generate and return token
        const token = this.generateToken(user);
        return {
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            }
        };
    }
}

// Authentication middleware
const authenticate = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const token = authHeader.substring(7);
        const authService = new AuthService();
        const decoded = await authService.verifyToken(token);
        
        // Attach user info to request
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

module.exports = {
    AuthService,
    authenticate
};
