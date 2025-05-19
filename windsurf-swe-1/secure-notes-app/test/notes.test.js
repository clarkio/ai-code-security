const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const { app } = require('../src/server');
const User = require('../src/models/User');
const Note = require('../src/models/Note');

let mongoServer;
let server;
let authToken;
let testUser;
let testNote;

// Test user data
const userData = {
  name: 'Test User',
  email: 'test@example.com',
  password: 'Test123!@#',
  passwordConfirm: 'Test123!@#'
};

// Test note data
const noteData = {
  title: 'Test Note',
  content: 'This is a test note content.',
  tags: ['test', 'important'],
  isPinned: false
};

beforeAll(async () => {
  // Start an in-memory MongoDB server for testing
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  
  // Connect to the in-memory database
  await mongoose.connect(mongoUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
  
  // Start the server on a random port
  server = app.listen(0);
  
  // Create a test user and get auth token
  await request(server)
    .post('/api/v1/auth/signup')
    .send(userData);
    
  const loginRes = await request(server)
    .post('/api/v1/auth/login')
    .send({
      email: userData.email,
      password: userData.password
    });
    
  authToken = loginRes.body.data.token;
  testUser = loginRes.body.data.user;
  
  // Create a test note
  const noteRes = await request(server)
    .post('/api/v1/notes')
    .set('Authorization', `Bearer ${authToken}`)
    .send(noteData);
    
  testNote = noteRes.body.data.note;
});

afterAll(async () => {
  // Close the server and database connection
  await server.close();
  await mongoose.disconnect();
  await mongoServer.stop();
});

describe('Notes API', () => {
  describe('GET /api/v1/notes', () => {
    it('should get all notes for the authenticated user', async () => {
      const res = await request(server)
        .get('/api/v1/notes')
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.status).toBe('success');
      expect(Array.isArray(res.body.data.notes)).toBe(true);
      expect(res.body.results).toBeGreaterThanOrEqual(1);
      
      // Check if the test note is in the response
      const note = res.body.data.notes.find(n => n._id === testNote._id);
      expect(note).toBeDefined();
      expect(note.title).toBe(testNote.title);
      expect(note.content).toBe(testNote.content);
    });

    it('should return 401 if not authenticated', async () => {
      const res = await request(server)
        .get('/api/v1/notes');
      
      expect(res.statusCode).toBe(401);
      expect(res.body.status).toBe('fail');
      expect(res.body.message).toContain('You are not logged in');
    });
  });

  describe('GET /api/v1/notes/:id', () => {
    it('should get a single note by ID', async () => {
      const res = await request(server)
        .get(`/api/v1/notes/${testNote._id}`)
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data.note._id).toBe(testNote._id);
      expect(res.body.data.note.title).toBe(testNote.title);
      expect(res.body.data.note.content).toBe(testNote.content);
    });

    it('should return 404 if note is not found', async () => {
      const nonExistentId = new mongoose.Types.ObjectId();
      const res = await request(server)
        .get(`/api/v1/notes/${nonExistentId}`)
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(res.statusCode).toBe(404);
      expect(res.body.status).toBe('fail');
      expect(res.body.message).toContain('No note found with that ID');
    });

    it('should return 400 if ID is invalid', async () => {
      const res = await request(server)
        .get('/api/v1/notes/invalid-id')
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(res.statusCode).toBe(400);
      expect(res.body.status).toBe('fail');
      expect(res.body.message).toContain('Invalid ID');
    });
  });

  describe('POST /api/v1/notes', () => {
    const newNote = {
      title: 'New Test Note',
      content: 'This is a new test note content.',
      tags: ['test', 'new'],
      isPinned: true
    };

    it('should create a new note', async () => {
      const res = await request(server)
        .post('/api/v1/notes')
        .set('Authorization', `Bearer ${authToken}`)
        .send(newNote);
      
      expect(res.statusCode).toBe(201);
      expect(res.body.status).toBe('success');
      expect(res.body.data.note.title).toBe(newNote.title);
      expect(res.body.data.note.content).toBe(newNote.content);
      expect(res.body.data.note.tags).toEqual(expect.arrayContaining(newNote.tags));
      expect(res.body.data.note.isPinned).toBe(newNote.isPinned);
      expect(res.body.data.note.user._id).toBe(testUser._id);
    });

    it('should return 400 if title is missing', async () => {
      const invalidNote = { ...newNote, title: '' };
      const res = await request(server)
        .post('/api/v1/notes')
        .set('Authorization', `Bearer ${authToken}`)
        .send(invalidNote);
      
      expect(res.statusCode).toBe(400);
      expect(res.body.status).toBe('fail');
      expect(res.body.message).toContain('Title must be between 1 and 100 characters');
    });
  });

  describe('PATCH /api/v1/notes/:id', () => {
    it('should update a note', async () => {
      const updates = {
        title: 'Updated Test Note',
        content: 'This is the updated content.',
        isPinned: true,
        tags: ['updated', 'important']
      };
      
      const res = await request(server)
        .patch(`/api/v1/notes/${testNote._id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updates);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data.note.title).toBe(updates.title);
      expect(res.body.data.note.content).toBe(updates.content);
      expect(res.body.data.note.isPinned).toBe(updates.isPinned);
      expect(res.body.data.note.tags).toEqual(expect.arrayContaining(updates.tags));
    });

    it('should return 404 if note is not found', async () => {
      const nonExistentId = new mongoose.Types.ObjectId();
      const res = await request(server)
        .patch(`/api/v1/notes/${nonExistentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ title: 'Updated Title' });
      
      expect(res.statusCode).toBe(404);
      expect(res.body.status).toBe('fail');
      expect(res.body.message).toContain('No note found with that ID');
    });
  });

  describe('DELETE /api/v1/notes/:id', () => {
    let noteToDelete;
    
    beforeEach(async () => {
      // Create a note to delete
      const res = await request(server)
        .post('/api/v1/notes')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          title: 'Note to delete',
          content: 'This note will be deleted',
          tags: ['temporary']
        });
      
      noteToDelete = res.body.data.note;
    });

    it('should delete a note', async () => {
      const res = await request(server)
        .delete(`/api/v1/notes/${noteToDelete._id}`)
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(res.statusCode).toBe(204);
      
      // Verify the note is deleted
      const deletedNote = await Note.findById(noteToDelete._id);
      expect(deletedNote).toBeNull();
    });

    it('should return 404 if note is not found', async () => {
      const nonExistentId = new mongoose.Types.ObjectId();
      const res = await request(server)
        .delete(`/api/v1/notes/${nonExistentId}`)
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(res.statusCode).toBe(404);
      expect(res.body.status).toBe('fail');
      expect(res.body.message).toContain('No note found with that ID');
    });
  });

  describe('GET /api/v1/notes/search', () => {
    beforeEach(async () => {
      // Create some test notes for search
      await request(server)
        .post('/api/v1/notes')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          title: 'Shopping List',
          content: 'Milk, eggs, bread, and cheese',
          tags: ['shopping', 'groceries']
        });
      
      await request(server)
        .post('/api/v1/notes')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          title: 'Work Tasks',
          content: 'Complete the project and submit the report',
          tags: ['work', 'important']
        });
    });

    it('should search notes by query string', async () => {
      const res = await request(server)
        .get('/api/v1/notes/search?q=shopping')
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.results).toBeGreaterThanOrEqual(1);
      expect(res.body.data.results[0].title).toContain('Shopping');
    });

    it('should return empty array if no matches found', async () => {
      const res = await request(server)
        .get('/api/v1/notes/search?q=nonexistentterm')
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data.results).toHaveLength(0);
    });
  });
});
