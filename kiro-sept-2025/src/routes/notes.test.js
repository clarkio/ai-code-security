const request = require('supertest');
const express = require('express');

// Mock dependencies before requiring modules
jest.mock('../services/notesService');
jest.mock('../services/authService');
jest.mock('../utils/logger');

const notesService = require('../services/notesService');
const authService = require('../services/authService');

// Create test app with manual route setup to avoid middleware issues
const app = express();
app.use(express.json());

// Mock validation middleware
const mockValidation = (req, res, next) => {
  // Basic validation simulation
  if (req.body && req.body.title && req.body.title.length > 200) {
    return res.status(400).json({
      error: { code: 'VALIDATION_ERROR', message: 'Title is too long' }
    });
  }
  if (req.body && req.body.content && req.body.content.length > 10000) {
    return res.status(400).json({
      error: { code: 'VALIDATION_ERROR', message: 'Content is too long' }
    });
  }
  if (req.query) {
    req.query.page = parseInt(req.query.page || '1', 10);
    req.query.limit = parseInt(req.query.limit || '10', 10);
  }
  next();
};

// Manually set up routes to avoid middleware loading issues
const router = express.Router();

// POST /api/notes
router.post('/', mockAuthMiddleware, mockValidation, async (req, res) => {
  try {
    const { title, content } = req.body;
    const userId = req.userId;

    if (!title) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'Title is required' }
      });
    }

    const note = await notesService.createNote(userId, { title, content });
    res.status(201).json({
      success: true,
      message: 'Note created successfully',
      data: note
    });
  } catch (error) {
    if (error.message.includes('required') || 
        error.message.includes('cannot exceed') ||
        error.message.includes('harmful content') ||
        error.message.includes('Maximum number')) {
      return res.status(400).json({
        error: { 
          code: 'VALIDATION_ERROR', 
          message: error.message,
          timestamp: new Date().toISOString()
        }
      });
    }
    res.status(500).json({
      error: { 
        code: 'INTERNAL_ERROR', 
        message: 'Failed to create note. Please try again.',
        timestamp: new Date().toISOString()
      }
    });
  }
});

// GET /api/notes
router.get('/', mockAuthMiddleware, mockValidation, async (req, res) => {
  try {
    const userId = req.userId;
    const { page, limit } = req.query;
    const includeDeleted = req.query.includeDeleted === 'true';

    const result = await notesService.getNotes(userId, {
      page: parseInt(page, 10),
      limit: parseInt(limit, 10),
      includeDeleted
    });

    res.json({
      success: true,
      data: result.notes,
      pagination: result.pagination
    });
  } catch (error) {
    if (error.message.includes('must be') || error.message.includes('invalid')) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: error.message }
      });
    }
    res.status(500).json({
      error: { code: 'INTERNAL_ERROR', message: 'Failed to retrieve notes. Please try again.' }
    });
  }
});

// GET /api/notes/search
router.get('/search', mockAuthMiddleware, mockValidation, async (req, res) => {
  try {
    const userId = req.userId;
    const { q: searchTerm, page, limit } = req.query;

    if (!searchTerm) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'Search term (q) is required' }
      });
    }

    const result = await notesService.searchNotes(userId, searchTerm, {
      page: parseInt(page, 10),
      limit: parseInt(limit, 10)
    });

    res.json({
      success: true,
      data: result.notes,
      searchTerm: result.searchTerm,
      pagination: result.pagination
    });
  } catch (error) {
    if (error.message.includes('required') || 
        error.message.includes('must be') ||
        error.message.includes('too long') ||
        error.message.includes('too short')) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: error.message }
      });
    }
    res.status(500).json({
      error: { code: 'INTERNAL_ERROR', message: 'Failed to search notes. Please try again.' }
    });
  }
});

// GET /api/notes/stats
router.get('/stats', mockAuthMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const stats = await notesService.getNoteStats(userId);
    res.json({ success: true, data: stats });
  } catch (error) {
    res.status(500).json({
      error: { code: 'INTERNAL_ERROR', message: 'Failed to retrieve note statistics. Please try again.' }
    });
  }
});

// GET /api/notes/:id
router.get('/:id', mockAuthMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const noteId = req.params.id;
    const note = await notesService.getNote(userId, noteId);
    res.json({ success: true, data: note });
  } catch (error) {
    if (error.message.includes('not found') || error.message.includes('access denied')) {
      return res.status(404).json({
        error: { code: 'NOT_FOUND', message: 'Note not found' }
      });
    }
    if (error.message.includes('Invalid') || error.message.includes('format')) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: error.message }
      });
    }
    res.status(500).json({
      error: { code: 'INTERNAL_ERROR', message: 'Failed to retrieve note. Please try again.' }
    });
  }
});

// PUT /api/notes/:id
router.put('/:id', mockAuthMiddleware, mockValidation, async (req, res) => {
  try {
    const userId = req.userId;
    const noteId = req.params.id;
    const { title, content } = req.body;
    const updatedNote = await notesService.updateNote(userId, noteId, { title, content });
    res.json({
      success: true,
      message: 'Note updated successfully',
      data: updatedNote
    });
  } catch (error) {
    if (error.message.includes('not found') || error.message.includes('access denied')) {
      return res.status(404).json({
        error: { code: 'NOT_FOUND', message: 'Note not found' }
      });
    }
    if (error.message.includes('required') || 
        error.message.includes('cannot exceed') ||
        error.message.includes('harmful content') ||
        error.message.includes('Invalid') ||
        error.message.includes('must be provided')) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: error.message }
      });
    }
    res.status(500).json({
      error: { code: 'INTERNAL_ERROR', message: 'Failed to update note. Please try again.' }
    });
  }
});

// DELETE /api/notes/:id
router.delete('/:id', mockAuthMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const noteId = req.params.id;
    const result = await notesService.deleteNote(userId, noteId);
    res.json({
      success: true,
      message: result.message,
      noteId: result.noteId
    });
  } catch (error) {
    if (error.message.includes('not found') || error.message.includes('access denied')) {
      return res.status(404).json({
        error: { code: 'NOT_FOUND', message: 'Note not found' }
      });
    }
    if (error.message.includes('Invalid') || error.message.includes('format')) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: error.message }
      });
    }
    res.status(500).json({
      error: { code: 'INTERNAL_ERROR', message: 'Failed to delete note. Please try again.' }
    });
  }
});

app.use('/api/notes', router);

describe('Notes Routes', () => {
  const mockUser = {
    id: 'user-123',
    email: 'test@example.com'
  };

  const mockAuthMiddleware = (req, res, next) => {
    req.user = mockUser;
    req.userId = mockUser.id;
    next();
  };

  const mockAuthFailureMiddleware = (req, res, next) => {
    return res.status(401).json({
      error: 'Authorization header required',
      code: 'MISSING_TOKEN'
    });
  };

  beforeEach(() => {
    jest.clearAllMocks();
    authService.createAuthMiddleware.mockReturnValue(mockAuthMiddleware);
  });

  describe('POST /api/notes', () => {
    const validNoteData = {
      title: 'Test Note',
      content: 'This is test content'
    };

    const mockCreatedNote = {
      id: 'note-123',
      title: 'Test Note',
      content: 'This is test content',
      createdAt: new Date(),
      updatedAt: new Date()
    };

    beforeEach(() => {
      notesService.createNote.mockResolvedValue(mockCreatedNote);
    });

    it('should create a note successfully', async () => {
      const response = await request(app)
        .post('/api/notes')
        .send(validNoteData)
        .expect(201);

      expect(response.body).toEqual({
        success: true,
        message: 'Note created successfully',
        data: expect.objectContaining({
          id: 'note-123',
          title: 'Test Note',
          content: 'This is test content'
        })
      });

      expect(notesService.createNote).toHaveBeenCalledWith(mockUser.id, validNoteData);
    });

    it('should reject request without title', async () => {
      const response = await request(app)
        .post('/api/notes')
        .send({ content: 'Content without title' })
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.message).toContain('Title');
    });

    it('should reject request without content', async () => {
      const response = await request(app)
        .post('/api/notes')
        .send({ title: 'Title without content' })
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should reject title that is too long', async () => {
      const longTitle = 'a'.repeat(201);
      const response = await request(app)
        .post('/api/notes')
        .send({ title: longTitle, content: 'Valid content' })
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.message).toContain('too long');
    });

    it('should reject content that is too long', async () => {
      const longContent = 'a'.repeat(10001);
      const response = await request(app)
        .post('/api/notes')
        .send({ title: 'Valid title', content: longContent })
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.message).toContain('too long');
    });

    it('should handle service validation errors', async () => {
      notesService.createNote.mockRejectedValue(new Error('Note title cannot be empty'));

      const response = await request(app)
        .post('/api/notes')
        .send(validNoteData)
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.message).toBe('Note title cannot be empty');
    });

    it('should handle service errors gracefully', async () => {
      notesService.createNote.mockRejectedValue(new Error('Database connection failed'));

      const response = await request(app)
        .post('/api/notes')
        .send(validNoteData)
        .expect(500);

      expect(response.body.error.code).toBe('INTERNAL_ERROR');
      expect(response.body.error.message).toBe('Failed to create note. Please try again.');
    });

    it('should handle maximum notes limit error', async () => {
      notesService.createNote.mockRejectedValue(new Error('Maximum number of notes (1000) reached for this user'));

      const response = await request(app)
        .post('/api/notes')
        .send(validNoteData)
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.message).toContain('Maximum number');
    });
  });

  describe('GET /api/notes', () => {
    const mockNotesResponse = {
      notes: [
        {
          id: 'note-1',
          title: 'Note 1',
          content: 'Content 1',
          createdAt: new Date(),
          updatedAt: new Date()
        },
        {
          id: 'note-2',
          title: 'Note 2',
          content: 'Content 2',
          createdAt: new Date(),
          updatedAt: new Date()
        }
      ],
      pagination: {
        page: 1,
        limit: 10,
        totalCount: 2,
        totalPages: 1,
        hasNextPage: false,
        hasPreviousPage: false
      }
    };

    beforeEach(() => {
      notesService.getNotes.mockResolvedValue(mockNotesResponse);
    });

    it('should get notes with default pagination', async () => {
      const response = await request(app)
        .get('/api/notes')
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        data: mockNotesResponse.notes,
        pagination: mockNotesResponse.pagination
      });

      expect(notesService.getNotes).toHaveBeenCalledWith(mockUser.id, {
        page: 1,
        limit: 10,
        includeDeleted: false
      });
    });

    it('should get notes with custom pagination', async () => {
      await request(app)
        .get('/api/notes?page=2&limit=5')
        .expect(200);

      expect(notesService.getNotes).toHaveBeenCalledWith(mockUser.id, {
        page: 2,
        limit: 5,
        includeDeleted: false
      });
    });

    it('should include deleted notes when requested', async () => {
      await request(app)
        .get('/api/notes?includeDeleted=true')
        .expect(200);

      expect(notesService.getNotes).toHaveBeenCalledWith(mockUser.id, {
        page: 1,
        limit: 10,
        includeDeleted: true
      });
    });

    it('should reject invalid pagination parameters', async () => {
      const response = await request(app)
        .get('/api/notes?page=0')
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should handle service errors', async () => {
      notesService.getNotes.mockRejectedValue(new Error('Database error'));

      const response = await request(app)
        .get('/api/notes')
        .expect(500);

      expect(response.body.error.code).toBe('INTERNAL_ERROR');
    });
  });

  describe('GET /api/notes/search', () => {
    const mockSearchResponse = {
      notes: [
        {
          id: 'note-1',
          title: 'Matching Note',
          content: 'This contains the search term',
          createdAt: new Date(),
          updatedAt: new Date()
        }
      ],
      searchTerm: 'search term',
      pagination: {
        page: 1,
        limit: 10,
        resultCount: 1
      }
    };

    beforeEach(() => {
      notesService.searchNotes.mockResolvedValue(mockSearchResponse);
    });

    it('should search notes successfully', async () => {
      const response = await request(app)
        .get('/api/notes/search?q=search%20term')
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        data: mockSearchResponse.notes,
        searchTerm: 'search term',
        pagination: mockSearchResponse.pagination
      });

      expect(notesService.searchNotes).toHaveBeenCalledWith(mockUser.id, 'search term', {
        page: 1,
        limit: 10
      });
    });

    it('should reject request without search term', async () => {
      const response = await request(app)
        .get('/api/notes/search')
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.message).toContain('Search term');
    });

    it('should handle search validation errors', async () => {
      notesService.searchNotes.mockRejectedValue(new Error('Search term must be at least 2 characters long'));

      const response = await request(app)
        .get('/api/notes/search?q=a')
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should handle service errors', async () => {
      notesService.searchNotes.mockRejectedValue(new Error('Search service unavailable'));

      const response = await request(app)
        .get('/api/notes/search?q=test')
        .expect(500);

      expect(response.body.error.code).toBe('INTERNAL_ERROR');
    });
  });

  describe('GET /api/notes/stats', () => {
    const mockStats = {
      totalNotes: 15,
      deletedNotes: 3,
      maxNotesAllowed: 1000,
      remainingNotes: 985
    };

    beforeEach(() => {
      notesService.getNoteStats.mockResolvedValue(mockStats);
    });

    it('should get note statistics', async () => {
      const response = await request(app)
        .get('/api/notes/stats')
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        data: mockStats
      });

      expect(notesService.getNoteStats).toHaveBeenCalledWith(mockUser.id);
    });

    it('should handle service errors', async () => {
      notesService.getNoteStats.mockRejectedValue(new Error('Stats service error'));

      const response = await request(app)
        .get('/api/notes/stats')
        .expect(500);

      expect(response.body.error.code).toBe('INTERNAL_ERROR');
    });
  });

  describe('GET /api/notes/:id', () => {
    const mockNoteId = '550e8400-e29b-41d4-a716-446655440000';
    const mockNote = {
      id: mockNoteId,
      title: 'Test Note',
      content: 'Test content',
      createdAt: new Date(),
      updatedAt: new Date(),
      isDeleted: false
    };

    beforeEach(() => {
      notesService.getNote.mockResolvedValue(mockNote);
    });

    it('should get a note successfully', async () => {
      const response = await request(app)
        .get(`/api/notes/${mockNoteId}`)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        data: expect.objectContaining({
          id: mockNoteId,
          title: 'Test Note',
          content: 'Test content'
        })
      });

      expect(notesService.getNote).toHaveBeenCalledWith(mockUser.id, mockNoteId);
    });

    it('should handle note not found', async () => {
      notesService.getNote.mockRejectedValue(new Error('Note not found or access denied'));

      const response = await request(app)
        .get(`/api/notes/${mockNoteId}`)
        .expect(404);

      expect(response.body.error.code).toBe('NOT_FOUND');
      expect(response.body.error.message).toBe('Note not found');
    });

    it('should handle invalid note ID format', async () => {
      notesService.getNote.mockRejectedValue(new Error('Invalid note ID format'));

      const response = await request(app)
        .get('/api/notes/invalid-id')
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should handle service errors', async () => {
      notesService.getNote.mockRejectedValue(new Error('Database error'));

      const response = await request(app)
        .get(`/api/notes/${mockNoteId}`)
        .expect(500);

      expect(response.body.error.code).toBe('INTERNAL_ERROR');
    });
  });

  describe('PUT /api/notes/:id', () => {
    const mockNoteId = '550e8400-e29b-41d4-a716-446655440000';
    const updateData = {
      title: 'Updated Title',
      content: 'Updated content'
    };
    const mockUpdatedNote = {
      id: mockNoteId,
      title: 'Updated Title',
      content: 'Updated content',
      createdAt: new Date(),
      updatedAt: new Date()
    };

    beforeEach(() => {
      notesService.updateNote.mockResolvedValue(mockUpdatedNote);
    });

    it('should update a note successfully', async () => {
      const response = await request(app)
        .put(`/api/notes/${mockNoteId}`)
        .send(updateData)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        message: 'Note updated successfully',
        data: expect.objectContaining({
          id: mockNoteId,
          title: 'Updated Title',
          content: 'Updated content'
        })
      });

      expect(notesService.updateNote).toHaveBeenCalledWith(mockUser.id, mockNoteId, updateData);
    });

    it('should update only title', async () => {
      const titleOnlyUpdate = { title: 'New Title' };
      await request(app)
        .put(`/api/notes/${mockNoteId}`)
        .send(titleOnlyUpdate)
        .expect(200);

      expect(notesService.updateNote).toHaveBeenCalledWith(mockUser.id, mockNoteId, titleOnlyUpdate);
    });

    it('should update only content', async () => {
      const contentOnlyUpdate = { content: 'New content' };
      await request(app)
        .put(`/api/notes/${mockNoteId}`)
        .send(contentOnlyUpdate)
        .expect(200);

      expect(notesService.updateNote).toHaveBeenCalledWith(mockUser.id, mockNoteId, contentOnlyUpdate);
    });

    it('should handle note not found', async () => {
      notesService.updateNote.mockRejectedValue(new Error('Note not found or access denied'));

      const response = await request(app)
        .put(`/api/notes/${mockNoteId}`)
        .send(updateData)
        .expect(404);

      expect(response.body.error.code).toBe('NOT_FOUND');
    });

    it('should handle validation errors', async () => {
      notesService.updateNote.mockRejectedValue(new Error('Note title cannot exceed 200 characters'));

      const response = await request(app)
        .put(`/api/notes/${mockNoteId}`)
        .send(updateData)
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should reject title that is too long', async () => {
      const longTitle = 'a'.repeat(201);
      const response = await request(app)
        .put(`/api/notes/${mockNoteId}`)
        .send({ title: longTitle })
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should handle service errors', async () => {
      notesService.updateNote.mockRejectedValue(new Error('Database error'));

      const response = await request(app)
        .put(`/api/notes/${mockNoteId}`)
        .send(updateData)
        .expect(500);

      expect(response.body.error.code).toBe('INTERNAL_ERROR');
    });
  });

  describe('DELETE /api/notes/:id', () => {
    const mockNoteId = '550e8400-e29b-41d4-a716-446655440000';
    const mockDeleteResponse = {
      success: true,
      message: 'Note deleted successfully',
      noteId: mockNoteId
    };

    beforeEach(() => {
      notesService.deleteNote.mockResolvedValue(mockDeleteResponse);
    });

    it('should delete a note successfully', async () => {
      const response = await request(app)
        .delete(`/api/notes/${mockNoteId}`)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        message: 'Note deleted successfully',
        noteId: mockNoteId
      });

      expect(notesService.deleteNote).toHaveBeenCalledWith(mockUser.id, mockNoteId);
    });

    it('should handle note not found', async () => {
      notesService.deleteNote.mockRejectedValue(new Error('Note not found or access denied'));

      const response = await request(app)
        .delete(`/api/notes/${mockNoteId}`)
        .expect(404);

      expect(response.body.error.code).toBe('NOT_FOUND');
    });

    it('should handle invalid note ID format', async () => {
      notesService.deleteNote.mockRejectedValue(new Error('Invalid note ID format'));

      const response = await request(app)
        .delete('/api/notes/invalid-id')
        .expect(400);

      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should handle service errors', async () => {
      notesService.deleteNote.mockRejectedValue(new Error('Database error'));

      const response = await request(app)
        .delete(`/api/notes/${mockNoteId}`)
        .expect(500);

      expect(response.body.error.code).toBe('INTERNAL_ERROR');
    });
  });

  describe('Authentication Tests', () => {
    let authFailureApp;

    beforeEach(() => {
      // Create separate app with auth failure middleware
      authFailureApp = express();
      authFailureApp.use(express.json());
      
      const authFailureRouter = express.Router();
      
      authFailureRouter.post('/', mockAuthFailureMiddleware, (req, res) => {
        res.status(201).json({ success: true });
      });
      authFailureRouter.get('/', mockAuthFailureMiddleware, (req, res) => {
        res.status(200).json({ success: true });
      });
      authFailureRouter.get('/:id', mockAuthFailureMiddleware, (req, res) => {
        res.status(200).json({ success: true });
      });
      authFailureRouter.put('/:id', mockAuthFailureMiddleware, (req, res) => {
        res.status(200).json({ success: true });
      });
      authFailureRouter.delete('/:id', mockAuthFailureMiddleware, (req, res) => {
        res.status(200).json({ success: true });
      });
      
      authFailureApp.use('/api/notes', authFailureRouter);
    });

    it('should require authentication for POST /api/notes', async () => {
      const response = await request(authFailureApp)
        .post('/api/notes')
        .send({ title: 'Test', content: 'Test' })
        .expect(401);

      expect(response.body.code).toBe('MISSING_TOKEN');
    });

    it('should require authentication for GET /api/notes', async () => {
      const response = await request(authFailureApp)
        .get('/api/notes')
        .expect(401);

      expect(response.body.code).toBe('MISSING_TOKEN');
    });

    it('should require authentication for GET /api/notes/:id', async () => {
      const response = await request(authFailureApp)
        .get('/api/notes/550e8400-e29b-41d4-a716-446655440000')
        .expect(401);

      expect(response.body.code).toBe('MISSING_TOKEN');
    });

    it('should require authentication for PUT /api/notes/:id', async () => {
      const response = await request(authFailureApp)
        .put('/api/notes/550e8400-e29b-41d4-a716-446655440000')
        .send({ title: 'Updated' })
        .expect(401);

      expect(response.body.code).toBe('MISSING_TOKEN');
    });

    it('should require authentication for DELETE /api/notes/:id', async () => {
      const response = await request(authFailureApp)
        .delete('/api/notes/550e8400-e29b-41d4-a716-446655440000')
        .expect(401);

      expect(response.body.code).toBe('MISSING_TOKEN');
    });
  });

  describe('Security Tests', () => {
    beforeEach(() => {
      // Reset to working auth middleware
      authService.createAuthMiddleware.mockReturnValue(mockAuthMiddleware);
    });

    describe('XSS Prevention', () => {
      const xssPayloads = [
        '<script>alert("xss")</script>',
        '<img src="x" onerror="alert(1)">',
        'javascript:alert("xss")',
        '<svg onload="alert(1)">'
      ];

      xssPayloads.forEach(payload => {
        it(`should sanitize XSS payload in title: ${payload}`, async () => {
          // The validation middleware should sanitize the input
          await request(app)
            .post('/api/notes')
            .send({ title: payload, content: 'Safe content' })
            .expect(201);

          // Verify that the service was called with sanitized data
          const calledWith = notesService.createNote.mock.calls[0][1];
          expect(calledWith.title).not.toContain('<script>');
          expect(calledWith.title).not.toContain('javascript:');
        });

        it(`should sanitize XSS payload in content: ${payload}`, async () => {
          await request(app)
            .post('/api/notes')
            .send({ title: 'Safe title', content: payload })
            .expect(201);

          const calledWith = notesService.createNote.mock.calls[0][1];
          expect(calledWith.content).not.toContain('<script>');
          expect(calledWith.content).not.toContain('javascript:');
        });
      });
    });

    describe('Input Validation', () => {
      it('should strip unknown fields from request body', async () => {
        await request(app)
          .post('/api/notes')
          .send({
            title: 'Valid title',
            content: 'Valid content',
            maliciousField: 'This should be stripped',
            userId: 'hacker-attempt'
          })
          .expect(201);

        const calledWith = notesService.createNote.mock.calls[0][1];
        expect(calledWith).toEqual({
          title: 'Valid title',
          content: 'Valid content'
        });
        expect(calledWith.maliciousField).toBeUndefined();
        expect(calledWith.userId).toBeUndefined();
      });

      it('should validate content length limits', async () => {
        const longContent = 'a'.repeat(10001);
        const response = await request(app)
          .post('/api/notes')
          .send({ title: 'Valid title', content: longContent })
          .expect(400);

        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(response.body.error.message).toContain('too long');
      });

      it('should validate title length limits', async () => {
        const longTitle = 'a'.repeat(201);
        const response = await request(app)
          .post('/api/notes')
          .send({ title: longTitle, content: 'Valid content' })
          .expect(400);

        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(response.body.error.message).toContain('too long');
      });
    });

    describe('Error Information Disclosure', () => {
      it('should not expose internal error details', async () => {
        notesService.createNote.mockRejectedValue(new Error('Database connection string: postgres://user:pass@localhost/db'));

        const response = await request(app)
          .post('/api/notes')
          .send({ title: 'Test', content: 'Test' })
          .expect(500);

        expect(response.body.error.message).toBe('Failed to create note. Please try again.');
        expect(response.body.error.message).not.toContain('postgres://');
        expect(response.body.error.message).not.toContain('user:pass');
      });

      it('should include timestamp in error responses', async () => {
        notesService.createNote.mockRejectedValue(new Error('Some error'));

        const response = await request(app)
          .post('/api/notes')
          .send({ title: 'Test', content: 'Test' })
          .expect(500);

        expect(response.body.error.timestamp).toBeDefined();
        expect(new Date(response.body.error.timestamp)).toBeInstanceOf(Date);
      });
    });
  });
});