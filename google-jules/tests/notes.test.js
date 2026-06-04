const request = require('supertest');
const app = require('../app'); // Adjust path as necessary
const { initializeTestDB, clearTestDB, describeWithDB } = require('./testSetup');

describeWithDB('Notes API', () => {
    let agent;
    let authToken;
    let csrfToken;
    let userId;

    // Helper to register and login a user, then get CSRF token
    const setupUserAndGetTokens = async (username, email, password) => {
        // Reset tokens at the beginning of setup to ensure freshness for each call
        authToken = null;
        csrfToken = null;
        userId = null;

        // Register user
        const regRes = await agent.post('/api/auth/register').send({ username, email, password });
        if (regRes.statusCode !== 201 && regRes.statusCode !== 400) { // Allow 400 if user already exists from a previous failed test run segment
            // console.error('Registration failed in setupUserAndGetTokens:', regRes.body);
            throw new Error(`Registration failed with status ${regRes.statusCode}`);
        }


        // Login user
        const loginRes = await agent.post('/api/auth/login').send({ email, password });
        if (loginRes.statusCode !== 200) {
            // console.error('Login failed in setupUserAndGetTokens:', loginRes.body);
            throw new Error(`Login failed with status ${loginRes.statusCode}`);
        }
        authToken = loginRes.body.token;
        
        // Extract user ID from token (for more complex scenarios, not strictly needed for these tests if API behaves correctly)
        // This is a simplified way, in a real app you might decode the JWT.
        // For testing, we can often infer user ID from successful operations or by creating specific users.
        // For this test, we'll assume the API correctly associates notes with the logged-in user.
        // If we needed to check user_id in the database directly, we'd need the ID.
        // Let's assume after login, the authMiddleware correctly sets req.user.id

        // Get CSRF token
        const csrfRes = await agent.get('/api/auth/csrf-token');
        csrfToken = csrfRes.body.csrfToken;
    };
    
    beforeEach(async () => {
        agent = request.agent(app); // Use agent to persist cookies (like _csrf)
        // Setup a default user for note operations
        await setupUserAndGetTokens('noteuser', 'notes@example.com', 'password123');
    });

    describe('POST /api/notes - Create Note', () => {
        it('should create a new note successfully', async () => {
            const res = await agent
                .post('/api/notes')
                .set('Authorization', `Bearer ${authToken}`)
                .set('X-CSRF-Token', csrfToken)
                .send({ title: 'Test Note', content: 'This is a test note.' });
            
            expect(res.statusCode).toEqual(201);
            expect(res.body).toHaveProperty('id');
            expect(res.body.title).toBe('Test Note');
            expect(res.body.content).toBe('This is a test note.');
        });

        it('should not create a note without auth token', async () => {
            const res = await agent
                .post('/api/notes')
                .set('X-CSRF-Token', csrfToken) // Sending CSRF token but no auth
                .send({ title: 'No Auth Note', content: 'Content' });
            expect(res.statusCode).toEqual(401); // Expecting 'No token, authorization denied'
            expect(res.body.msg).toEqual('No token, authorization denied');
        });

        it('should not create a note without CSRF token', async () => {
            const res = await agent
                .post('/api/notes')
                .set('Authorization', `Bearer ${authToken}`) // Sending Auth token but no CSRF
                .send({ title: 'No CSRF Note', content: 'Content' });
            expect(res.statusCode).toEqual(403); // Expecting 'Invalid CSRF token'
            expect(res.body.message).toEqual('Invalid CSRF token. Please refresh and try again.');
        });

        it('should not create a note with missing title', async () => {
            const res = await agent
                .post('/api/notes')
                .set('Authorization', `Bearer ${authToken}`)
                .set('X-CSRF-Token', csrfToken)
                .send({ content: 'This note has no title.' });
            expect(res.statusCode).toEqual(400);
            const errors = res.body.errors;
            expect(errors).toBeInstanceOf(Array);
            expect(errors.some(err => err.path === 'title' && err.msg === 'Title is required')).toBe(true);
        });
    });

    describe('GET /api/notes - Get Notes', () => {
        beforeEach(async () => {
            // Create some notes for the user
            await agent.post('/api/notes').set('Authorization', `Bearer ${authToken}`).set('X-CSRF-Token', csrfToken).send({ title: 'Note 1', content: 'Content 1' });
            await agent.post('/api/notes').set('Authorization', `Bearer ${authToken}`).set('X-CSRF-Token', csrfToken).send({ title: 'Note 2', content: 'Content 2' });
        });

        it('should get all notes for the authenticated user', async () => {
            const res = await agent
                .get('/api/notes')
                .set('Authorization', `Bearer ${authToken}`);
            
            expect(res.statusCode).toEqual(200);
            expect(res.body).toBeInstanceOf(Array);
            expect(res.body.length).toBe(2);
            // Check for presence of notes, order might vary slightly due to timestamp precision
            expect(res.body.some(note => note.title === 'Note 1')).toBe(true);
            expect(res.body.some(note => note.title === 'Note 2')).toBe(true);
        });

        it('should return an empty array if user has no notes', async () => {
            // Clear notes created in beforeEach for this specific test
            await clearTestDB(); // Clears all tables, need to re-register/login user
            await setupUserAndGetTokens('newnotesuser', 'newnotes@example.com', 'password123');


            const res = await agent
                .get('/api/notes')
                .set('Authorization', `Bearer ${authToken}`);
            
            expect(res.statusCode).toEqual(200);
            expect(res.body).toBeInstanceOf(Array);
            expect(res.body.length).toBe(0);
        });
    });

    describe('GET /api/notes/:id - Get Note By ID', () => {
        let noteId;

        beforeEach(async () => {
            const createRes = await agent.post('/api/notes').set('Authorization', `Bearer ${authToken}`).set('X-CSRF-Token', csrfToken).send({ title: 'Specific Note', content: 'Details' });
            noteId = createRes.body.id;
        });

        it('should get a specific note by ID for the authenticated user', async () => {
            const res = await agent
                .get(`/api/notes/${noteId}`)
                .set('Authorization', `Bearer ${authToken}`);
            
            expect(res.statusCode).toEqual(200);
            expect(res.body).toHaveProperty('id', noteId);
            expect(res.body.title).toBe('Specific Note');
        });

        it('should return 404 for a non-existent note ID', async () => {
            const res = await agent
                .get('/api/notes/99999') // Assuming 99999 does not exist
                .set('Authorization', `Bearer ${authToken}`);
            expect(res.statusCode).toEqual(404);
        });
        
        it('should return 404 if trying to get another user\'s note', async () => {
            // 1. Create a note with current user (noteuser) - done in beforeEach
            const firstNoteId = noteId;

            // 2. Setup another user
            let otherAgent = request.agent(app);
            await otherAgent.post('/api/auth/register').send({ username: 'otheruser', email: 'other@example.com', password: 'password123' });
            const otherLoginRes = await otherAgent.post('/api/auth/login').send({ email: 'other@example.com', password: 'password123' });
            const otherAuthToken = otherLoginRes.body.token;
            // CSRF for otherAgent not strictly needed for GET, but good practice if it were a state change
            
            // 3. Try to get firstNoteId using otherAuthToken
            const res = await otherAgent
                .get(`/api/notes/${firstNoteId}`)
                .set('Authorization', `Bearer ${otherAuthToken}`);
            
            expect(res.statusCode).toEqual(404); // Access denied should result in 404
        });
    });

    describe('PUT /api/notes/:id - Update Note', () => {
        let noteIdToUpdate;

        beforeEach(async () => {
            const createRes = await agent.post('/api/notes').set('Authorization', `Bearer ${authToken}`).set('X-CSRF-Token', csrfToken).send({ title: 'Update Me', content: 'Initial Content' });
            noteIdToUpdate = createRes.body.id;
        });

        it('should update an existing note successfully', async () => {
            const res = await agent
                .put(`/api/notes/${noteIdToUpdate}`)
                .set('Authorization', `Bearer ${authToken}`)
                .set('X-CSRF-Token', csrfToken)
                .send({ title: 'Updated Title', content: 'Updated Content' });
            
            expect(res.statusCode).toEqual(200);
            expect(res.body.title).toBe('Updated Title');
            expect(res.body.content).toBe('Updated Content');
        });

        it('should return 404 when trying to update a non-existent note', async () => {
            const res = await agent
                .put('/api/notes/99999')
                .set('Authorization', `Bearer ${authToken}`)
                .set('X-CSRF-Token', csrfToken)
                .send({ title: 'Non Existent', content: 'Content' });
            expect(res.statusCode).toEqual(404);
        });
        
        it('should not update another user\'s note', async () => {
            const firstNoteId = noteIdToUpdate; // Note created by 'noteuser'

            let otherAgent = request.agent(app);
            await otherAgent.post('/api/auth/register').send({ username: 'otheruser2', email: 'other2@example.com', password: 'password123' });
            const otherLoginRes = await otherAgent.post('/api/auth/login').send({ email: 'other2@example.com', password: 'password123' });
            const otherAuthToken = otherLoginRes.body.token;
            const csrfResOther = await otherAgent.get('/api/auth/csrf-token'); // CSRF for other user
            const otherCsrfToken = csrfResOther.body.csrfToken;

            const res = await otherAgent
                .put(`/api/notes/${firstNoteId}`)
                .set('Authorization', `Bearer ${otherAuthToken}`)
                .set('X-CSRF-Token', otherCsrfToken)
                .send({ title: 'Attempted Update', content: 'Should Fail' });
            
            expect(res.statusCode).toEqual(404); // Should be 404 as the note is not found for this user
        });
    });

    describe('DELETE /api/notes/:id - Delete Note', () => {
        let noteIdToDelete;

        beforeEach(async () => {
            const createRes = await agent.post('/api/notes').set('Authorization', `Bearer ${authToken}`).set('X-CSRF-Token', csrfToken).send({ title: 'Delete Me', content: 'Initial Content' });
            noteIdToDelete = createRes.body.id;
        });

        it('should delete an existing note successfully', async () => {
            const res = await agent
                .delete(`/api/notes/${noteIdToDelete}`)
                .set('Authorization', `Bearer ${authToken}`)
                .set('X-CSRF-Token', csrfToken);
            
            expect(res.statusCode).toEqual(200); // Or 204 if you prefer
            expect(res.body.msg).toBe('Note removed');

            // Verify note is actually deleted
            const getRes = await agent.get(`/api/notes/${noteIdToDelete}`).set('Authorization', `Bearer ${authToken}`);
            expect(getRes.statusCode).toEqual(404);
        });

        it('should return 404 when trying to delete a non-existent note', async () => {
            const res = await agent
                .delete('/api/notes/99999')
                .set('Authorization', `Bearer ${authToken}`)
                .set('X-CSRF-Token', csrfToken);
            expect(res.statusCode).toEqual(404);
        });
        
        it('should not delete another user\'s note', async () => {
            const firstNoteId = noteIdToDelete; // Note created by 'noteuser'

            let otherAgent = request.agent(app);
            await otherAgent.post('/api/auth/register').send({ username: 'otheruser3', email: 'other3@example.com', password: 'password123' });
            const otherLoginRes = await otherAgent.post('/api/auth/login').send({ email: 'other3@example.com', password: 'password123' });
            const otherAuthToken = otherLoginRes.body.token;
            const csrfResOther = await otherAgent.get('/api/auth/csrf-token');
            const otherCsrfToken = csrfResOther.body.csrfToken;

            const res = await otherAgent
                .delete(`/api/notes/${firstNoteId}`)
                .set('Authorization', `Bearer ${otherAuthToken}`)
                .set('X-CSRF-Token', otherCsrfToken);
            
            expect(res.statusCode).toEqual(404); // Should be 404 as the note is not found for this user
        });
    });
});
