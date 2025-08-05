const request = require('supertest');
const app = require('../src/app'); // Adjust the path as necessary
const User = require('../src/models/user');

describe('Authentication Tests', () => {
    beforeAll(async () => {
        await User.deleteMany({}); // Clear the database before tests
    });

    afterAll(async () => {
        await User.deleteMany({}); // Clean up after tests
    });

    it('should register a new user', async () => {
        const response = await request(app)
            .post('/api/auth/register')
            .send({
                username: 'testuser',
                password: 'Password123!',
            });
        expect(response.status).toBe(201);
        expect(response.body).toHaveProperty('token');
    });

    it('should login an existing user', async () => {
        await request(app)
            .post('/api/auth/register')
            .send({
                username: 'testuser',
                password: 'Password123!',
            });

        const response = await request(app)
            .post('/api/auth/login')
            .send({
                username: 'testuser',
                password: 'Password123!',
            });
        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('token');
    });

    it('should not login with incorrect password', async () => {
        const response = await request(app)
            .post('/api/auth/login')
            .send({
                username: 'testuser',
                password: 'WrongPassword!',
            });
        expect(response.status).toBe(401);
    });

    it('should not register a user with an existing username', async () => {
        await request(app)
            .post('/api/auth/register')
            .send({
                username: 'testuser',
                password: 'Password123!',
            });

        const response = await request(app)
            .post('/api/auth/register')
            .send({
                username: 'testuser',
                password: 'Password123!',
            });
        expect(response.status).toBe(400);
    });
});