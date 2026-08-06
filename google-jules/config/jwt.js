require('dotenv').config();

let jwtSecret = process.env.JWT_SECRET;
if (process.env.NODE_ENV === 'test' && !jwtSecret) {
    console.warn('JWT_SECRET not set for test environment, using default test secret.');
    jwtSecret = 'test_jwt_secret_for_automated_tests_12345!';
} else if (!jwtSecret) {
    // This case should ideally not happen in dev/prod if .env is set up correctly.
    console.error('FATAL ERROR: JWT_SECRET is not set. Application cannot securely sign JWTs.');
    // process.exit(1); // Or handle more gracefully depending on app requirements
}


module.exports = {
    secret: jwtSecret,
    expiresIn: '1h' // Token expiration time
};
