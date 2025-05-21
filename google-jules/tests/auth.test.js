const request = require('supertest');
const app = require('../app'); // Adjust path as necessary
const { initializeTestDB, clearTestDB, describeWithDB } = require('./testSetup'); // Using the wrapper

describeWithDB('Authentication API', () => {
    let agent; // To carry cookies like csurf cookie

    beforeEach(() => {
        agent = request.agent(app); // Create a new agent for each test to isolate cookies
    });

    describe('User Registration', () => {
        it('should register a new user successfully', async () => {
            const res = await agent
                .post('/api/auth/register')
                .send({
                    username: 'testuser',
                    email: 'test@example.com',
                    password: 'password123'
                });
            expect(res.statusCode).toEqual(201);
            expect(res.body).toHaveProperty('token');
            expect(res.body).toHaveProperty('message', 'User registered successfully');
        });

        it('should not register a user with an existing email', async () => {
            // First, register a user
            await agent
                .post('/api/auth/register')
                .send({
                    username: 'testuser1',
                    email: 'test@example.com',
                    password: 'password123'
                });
            
            // Attempt to register again with the same email
            const res = await agent
                .post('/api/auth/register')
                .send({
                    username: 'testuser2', // Different username
                    email: 'test@example.com', // Same email
                    password: 'password123'
                });
            expect(res.statusCode).toEqual(400);
            expect(res.body.errors[0].msg).toEqual('User already exists with this email');
        });

        it('should not register a user with an existing username', async () => {
            await agent
                .post('/api/auth/register')
                .send({
                    username: 'testuser',
                    email: 'test1@example.com',
                    password: 'password123'
                });

            const res = await agent
                .post('/api/auth/register')
                .send({
                    username: 'testuser', // Same username
                    email: 'test2@example.com', // Different email
                    password: 'password123'
                });
            expect(res.statusCode).toEqual(400);
            expect(res.body.errors[0].msg).toEqual('User already exists with this username');
        });

        it('should not register a user with missing fields', async () => {
            const res = await agent
                .post('/api/auth/register')
                .send({
                    email: 'test@example.com',
                    // Missing username and password
                });
            expect(res.statusCode).toEqual(400);
            // Check for specific error messages
            const errors = res.body.errors;
            expect(errors).toBeInstanceOf(Array);
            expect(errors.some(err => err.path === 'username' && err.msg === 'Username is required')).toBe(true);
            expect(errors.some(err => err.path === 'password' && err.msg === 'Password must be 6 or more characters')).toBe(true);
        });
    });

    describe('User Login', () => {
        beforeEach(async () => {
            // Register a user before each login test
            await agent
                .post('/api/auth/register')
                .send({
                    username: 'loginuser',
                    email: 'login@example.com',
                    password: 'password123'
                });
        });

        it('should login an existing user successfully', async () => {
            const res = await agent
                .post('/api/auth/login')
                .send({
                    email: 'login@example.com',
                    password: 'password123'
                });
            expect(res.statusCode).toEqual(200);
            expect(res.body).toHaveProperty('token');
        });

        it('should not login with incorrect password', async () => {
            const res = await agent
                .post('/api/auth/login')
                .send({
                    email: 'login@example.com',
                    password: 'wrongpassword'
                });
            expect(res.statusCode).toEqual(400); // Based on current authController setup
            expect(res.body.errors[0].msg).toEqual('Invalid Credentials');
        });

        it('should not login a non-existent user', async () => {
            const res = await agent
                .post('/api/auth/login')
                .send({
                    email: 'nonexistent@example.com',
                    password: 'password123'
                });
            expect(res.statusCode).toEqual(400); // Based on current authController setup
            expect(res.body.errors[0].msg).toEqual('Invalid Credentials');
        });
    });

    describe('CSRF Token Route', () => {
        it('should return a CSRF token', async () => {
            const res = await agent.get('/api/auth/csrf-token');
            expect(res.statusCode).toEqual(200);
            expect(res.body).toHaveProperty('csrfToken');
            expect(res.body.csrfToken).not.toBeNull();
            expect(res.body.csrfToken.length).toBeGreaterThan(0);

            // Check if the CSRF cookie is set
            const csrfCookie = res.headers['set-cookie'].find(cookie => cookie.startsWith('_csrf='));
            expect(csrfCookie).toBeDefined();
        });
    });
});
