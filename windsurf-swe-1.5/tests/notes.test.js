const request = require('supertest');
const app = require('../server');
const Note = require('../models/Note');

describe('Notes API', () => {
  let noteModel;
  let testNote;

  beforeAll(() => {
    noteModel = new Note();
  });

  beforeEach(() => {
    // Clear all notes before each test
    noteModel.notes = {};
    noteModel.saveNotes();
  });

  describe('GET /api/notes', () => {
    it('should return empty array when no notes exist', async () => {
      const response = await request(app)
        .get('/api/notes')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toEqual([]);
      expect(response.body.count).toBe(0);
    });

    it('should return all notes', async () => {
      testNote = noteModel.create({
        title: 'Test Note',
        content: 'Test content',
        tags: ['test']
      });

      const response = await request(app)
        .get('/api/notes')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveLength(1);
      expect(response.body.data[0].title).toBe('Test Note');
    });
  });

  describe('POST /api/notes', () => {
    it('should create a new note', async () => {
      const noteData = {
        title: 'New Test Note',
        content: 'New test content',
        tags: ['new', 'test']
      };

      const response = await request(app)
        .post('/api/notes')
        .set('X-CSRF-Token', 'test-token')
        .send(noteData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.title).toBe(noteData.title);
      expect(response.body.data.content).toBe(noteData.content);
      expect(response.body.data.tags).toEqual(noteData.tags);
      expect(response.body.data.id).toBeDefined();
      expect(response.body.data.createdAt).toBeDefined();
      expect(response.body.data.updatedAt).toBeDefined();
    });

    it('should reject note with missing title', async () => {
      const noteData = {
        content: 'Test content'
      };

      const response = await request(app)
        .post('/api/notes')
        .set('X-CSRF-Token', 'test-token')
        .send(noteData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Validation Error');
    });

    it('should reject note with HTML in title', async () => {
      const noteData = {
        title: '<script>alert("xss")</script>',
        content: 'Test content'
      };

      const response = await request(app)
        .post('/api/notes')
        .set('X-CSRF-Token', 'test-token')
        .send(noteData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Validation Error');
    });

    it('should reject note with too many tags', async () => {
      const noteData = {
        title: 'Test Note',
        content: 'Test content',
        tags: ['tag1', 'tag2', 'tag3', 'tag4', 'tag5', 'tag6', 'tag7', 'tag8', 'tag9', 'tag10', 'tag11']
      };

      const response = await request(app)
        .post('/api/notes')
        .set('X-CSRF-Token', 'test-token')
        .send(noteData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Validation Error');
    });
  });

  describe('GET /api/notes/:id', () => {
    beforeEach(() => {
      testNote = noteModel.create({
        title: 'Test Note',
        content: 'Test content',
        tags: ['test']
      });
    });

    it('should return a specific note', async () => {
      const response = await request(app)
        .get(`/api/notes/${testNote.id}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.id).toBe(testNote.id);
      expect(response.body.data.title).toBe('Test Note');
    });

    it('should return 404 for non-existent note', async () => {
      const fakeId = '550e8400-e29b-41d4-a716-446655440000';
      
      const response = await request(app)
        .get(`/api/notes/${fakeId}`)
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Note not found');
    });

    it('should reject invalid UUID format', async () => {
      const response = await request(app)
        .get('/api/notes/invalid-id')
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Validation Error');
    });
  });

  describe('PUT /api/notes/:id', () => {
    beforeEach(() => {
      testNote = noteModel.create({
        title: 'Test Note',
        content: 'Test content',
        tags: ['test']
      });
    });

    it('should update an existing note', async () => {
      const updateData = {
        title: 'Updated Note',
        content: 'Updated content'
      };

      const response = await request(app)
        .put(`/api/notes/${testNote.id}`)
        .set('X-CSRF-Token', 'test-token')
        .send(updateData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.title).toBe(updateData.title);
      expect(response.body.data.content).toBe(updateData.content);
      expect(response.body.data.updatedAt).not.toBe(testNote.updatedAt);
    });

    it('should return 404 for non-existent note', async () => {
      const fakeId = '550e8400-e29b-41d4-a716-446655440000';
      const updateData = { title: 'Updated' };

      const response = await request(app)
        .put(`/api/notes/${fakeId}`)
        .set('X-CSRF-Token', 'test-token')
        .send(updateData)
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Note not found');
    });

    it('should reject update with no fields', async () => {
      const response = await request(app)
        .put(`/api/notes/${testNote.id}`)
        .set('X-CSRF-Token', 'test-token')
        .send({})
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Validation Error');
    });
  });

  describe('DELETE /api/notes/:id', () => {
    beforeEach(() => {
      testNote = noteModel.create({
        title: 'Test Note',
        content: 'Test content',
        tags: ['test']
      });
    });

    it('should delete an existing note', async () => {
      const response = await request(app)
        .delete(`/api/notes/${testNote.id}`)
        .set('X-CSRF-Token', 'test-token')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Note deleted successfully');

      // Verify note is actually deleted
      const getResponse = await request(app)
        .get(`/api/notes/${testNote.id}`)
        .expect(404);
    });

    it('should return 404 for non-existent note', async () => {
      const fakeId = '550e8400-e29b-41d4-a716-446655440000';

      const response = await request(app)
        .delete(`/api/notes/${fakeId}`)
        .set('X-CSRF-Token', 'test-token')
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Note not found');
    });
  });

  describe('GET /api/notes/tags', () => {
    it('should return empty array when no tags exist', async () => {
      const response = await request(app)
        .get('/api/notes/tags')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toEqual([]);
      expect(response.body.count).toBe(0);
    });

    it('should return all unique tags', async () => {
      noteModel.create({ title: 'Note 1', content: 'Content 1', tags: ['tag1', 'tag2'] });
      noteModel.create({ title: 'Note 2', content: 'Content 2', tags: ['tag2', 'tag3'] });

      const response = await request(app)
        .get('/api/notes/tags')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toEqual(['tag1', 'tag2', 'tag3']);
      expect(response.body.count).toBe(3);
    });
  });
});
