const dotenv = require('dotenv');

dotenv.config();

const securityConfig = {
    jwtSecret: process.env.JWT_SECRET || 'your-default-secret-key',
    jwtExpiration: process.env.JWT_EXPIRATION || '1h',
    passwordSaltRounds: parseInt(process.env.PASSWORD_SALT_ROUNDS) || 10,
    apiRateLimit: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100 // limit each IP to 100 requests per windowMs
    },
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: []
        }
    }
};

module.exports = securityConfig;