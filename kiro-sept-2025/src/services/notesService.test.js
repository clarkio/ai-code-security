const notesService = require('./notesService');
const Note = require('../models/Note');
const logger = require('../utils/logger');

// Mock dependencies
jest.mock('../models/Note');
jest.mock('../utils/logger');

describe('NotesService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('createNote', () => {
    const mockUserId = 'user-123';
    const validNoteData = {
      title: 'Test Note',
      content: 'This is test content'
    };

    beforeEach(() => {
      Note.getCountByUserId.mockResolvedValue(5);
      Note.create.mockResolvedValue({
        id: 'note-123',
        title: 'Test Note',
        content: 'This is test content',
        createdAt: new Date(),
        updatedAt: new Date()
      });
    });

    it('should create a note successfully with valid data', async () => {
      const result = await notesService.createNote(mockUserId, validNoteData);

      expect(Note.getCountByUserId).toHaveBeenCalledWith(mockUserId);
      expect(Note.create).toHaveBeenCalledWith({
        userId: mockUserId,
        title: 'Test Note',
        content: 'This is test content'
      });
      expect(result).toEqual({
        id: 'note-123',
        title: 'Test Note',
        content: 'This is test content',
        createdAt: expect.any(Date),
        updatedAt: expect.any(Date)
      });
      expect(logger.security.dataModification).toHaveBeenCalledWith({
        action: 'note_created',
        userId: mockUserId,
        resource: 'note',
        resourceId: 'note-123',
        metadata: {
          titleLength: 9,
          contentLength: 20
        }
      });
    });

    it('should reject empty title', async () => {
      const invalidData = { title: '   ', content: 'Valid content' }; // whitespace only

      await expect(notesService.createNote(mockUserId, invalidData))
        .rejects.toThrow('Note title cannot be empty');
    });

    it('should reject missing title', async () => {
      const invalidData = { content: 'Valid content' };

      await expect(notesService.createNote(mockUserId, invalidData))
        .rejects.toThrow('Note title is required and must be a string');
    });

    it('should reject title that is too long', async () => {
      const longTitle = 'a'.repeat(201);
      const invalidData = { title: longTitle, content: 'Valid content' };

      await expect(notesService.createNote(mockUserId, invalidData))
        .rejects.toThrow('Note title cannot exceed 200 characters');
    });

    it('should reject content that is too long', async () => {
      const longContent = 'a'.repeat(10001);
      const invalidData = { title: 'Valid title', content: longContent };

      await expect(notesService.createNote(mockUserId, invalidData))
        .rejects.toThrow('Note content cannot exceed 10000 characters');
    });

    it('should reject malicious script content in title', async () => {
      const maliciousData = {
        title: '<script>alert("xss")</script>',
        content: 'Valid content'
      };

      await expect(notesService.createNote(mockUserId, maliciousData))
        .rejects.toThrow('Note title contains potentially harmful content');
    });

    it('should reject malicious script content in content', async () => {
      const maliciousData = {
        title: 'Valid title',
        content: '<script>alert("xss")</script>'
      };

      await expect(notesService.createNote(mockUserId, maliciousData))
        .rejects.toThrow('Note content contains potentially harmful content');
    });

    it('should reject when user has reached maximum notes limit', async () => {
      Note.getCountByUserId.mockResolvedValue(1000);

      await expect(notesService.createNote(mockUserId, validNoteData))
        .rejects.toThrow('Maximum number of notes (1000) reached for this user');
    });

    it('should trim whitespace from title and content', async () => {
      const dataWithWhitespace = {
        title: '  Test Note  ',
        content: '  This is test content  '
      };

      await notesService.createNote(mockUserId, dataWithWhitespace);

      expect(Note.create).toHaveBeenCalledWith({
        userId: mockUserId,
        title: 'Test Note',
        content: 'This is test content'
      });
    });

    it('should handle database errors gracefully', async () => {
      Note.create.mockRejectedValue(new Error('Database error'));

      await expect(notesService.createNote(mockUserId, validNoteData))
        .rejects.toThrow('Failed to create note. Please try again.');

      expect(logger.error).toHaveBeenCalledWith('Failed to create note', expect.any(Object));
    });
  });

  describe('getNotes', () => {
    const mockUserId = 'user-123';
    const mockNotes = [
      {
        id: 'note-1',
        title: 'Note 1',
        content: 'Content 1',
        createdAt: new Date(),
        updatedAt: new Date(),
        isDeleted: false
      },
      {
        id: 'note-2',
        title: 'Note 2',
        content: 'Content 2',
        createdAt: new Date(),
        updatedAt: new Date(),
        isDeleted: false
      }
    ];

    beforeEach(() => {
      Note.findByUserId.mockResolvedValue(mockNotes);
      Note.getCountByUserId.mockResolvedValue(25);
    });

    it('should get notes with default pagination', async () => {
      const result = await notesService.getNotes(mockUserId);

      expect(Note.findByUserId).toHaveBeenCalledWith(mockUserId, {
        limit: 10,
        offset: 0,
        includeDeleted: false
      });
      expect(Note.getCountByUserId).toHaveBeenCalledWith(mockUserId, false);
      expect(result.notes).toHaveLength(2);
      expect(result.pagination).toEqual({
        page: 1,
        limit: 10,
        totalCount: 25,
        totalPages: 3,
        hasNextPage: true,
        hasPreviousPage: false
      });
    });

    it('should get notes with custom pagination', async () => {
      const options = { page: 2, limit: 5 };
      await notesService.getNotes(mockUserId, options);

      expect(Note.findByUserId).toHaveBeenCalledWith(mockUserId, {
        limit: 5,
        offset: 5,
        includeDeleted: false
      });
    });

    it('should include deleted notes when requested', async () => {
      const options = { includeDeleted: true };
      await notesService.getNotes(mockUserId, options);

      expect(Note.findByUserId).toHaveBeenCalledWith(mockUserId, {
        limit: 10,
        offset: 0,
        includeDeleted: true
      });
      expect(Note.getCountByUserId).toHaveBeenCalledWith(mockUserId, true);
    });

    it('should validate pagination parameters', async () => {
      await expect(notesService.getNotes(mockUserId, { page: 0 }))
        .rejects.toThrow('Page must be a positive integer');

      await expect(notesService.getNotes(mockUserId, { page: 1001 }))
        .rejects.toThrow('Page number is too large (maximum 1000)');

      await expect(notesService.getNotes(mockUserId, { limit: 0 }))
        .rejects.toThrow('Limit must be a positive integer');

      await expect(notesService.getNotes(mockUserId, { limit: 101 }))
        .rejects.toThrow('Limit cannot exceed 100');
    });

    it('should log data access', async () => {
      await notesService.getNotes(mockUserId);

      expect(logger.security.dataAccess).toHaveBeenCalledWith({
        action: 'notes_retrieved',
        userId: mockUserId,
        resource: 'note',
        count: 2,
        pagination: { page: 1, limit: 10, totalCount: 25 }
      });
    });
  });

  describe('getNote', () => {
    const mockUserId = 'user-123';
    const mockNoteId = '550e8400-e29b-41d4-a716-446655440000';
    const mockNote = {
      id: mockNoteId,
      title: 'Test Note',
      content: 'Test content',
      createdAt: new Date(),
      updatedAt: new Date(),
      isDeleted: false
    };

    it('should get a note successfully', async () => {
      Note.findByIdAndUserId.mockResolvedValue(mockNote);

      const result = await notesService.getNote(mockUserId, mockNoteId);

      expect(Note.findByIdAndUserId).toHaveBeenCalledWith(mockNoteId, mockUserId);
      expect(result).toEqual({
        id: mockNoteId,
        title: 'Test Note',
        content: 'Test content',
        createdAt: expect.any(Date),
        updatedAt: expect.any(Date),
        isDeleted: false
      });
      expect(logger.security.dataAccess).toHaveBeenCalledWith({
        action: 'note_retrieved',
        userId: mockUserId,
        resource: 'note',
        resourceId: mockNoteId
      });
    });

    it('should reject invalid note ID format', async () => {
      await expect(notesService.getNote(mockUserId, 'invalid-id'))
        .rejects.toThrow('Invalid note ID format');
    });

    it('should handle note not found', async () => {
      Note.findByIdAndUserId.mockResolvedValue(null);

      await expect(notesService.getNote(mockUserId, mockNoteId))
        .rejects.toThrow('Note not found or access denied');
    });

    it('should handle database errors', async () => {
      Note.findByIdAndUserId.mockRejectedValue(new Error('Database error'));

      await expect(notesService.getNote(mockUserId, mockNoteId))
        .rejects.toThrow('Failed to retrieve note. Please try again.');
    });
  });

  describe('updateNote', () => {
    const mockUserId = 'user-123';
    const mockNoteId = '550e8400-e29b-41d4-a716-446655440000';
    const mockNote = {
      id: mockNoteId,
      title: 'Original Title',
      content: 'Original content',
      update: jest.fn()
    };

    beforeEach(() => {
      Note.findByIdAndUserId.mockResolvedValue(mockNote);
      mockNote.update.mockResolvedValue({
        id: mockNoteId,
        title: 'Updated Title',
        content: 'Updated content',
        createdAt: new Date(),
        updatedAt: new Date()
      });
    });

    it('should update note title successfully', async () => {
      const updateData = { title: 'Updated Title' };
      const result = await notesService.updateNote(mockUserId, mockNoteId, updateData);

      expect(Note.findByIdAndUserId).toHaveBeenCalledWith(mockNoteId, mockUserId);
      expect(mockNote.update).toHaveBeenCalledWith({ title: 'Updated Title' });
      expect(result.title).toBe('Updated Title');
    });

    it('should update note content successfully', async () => {
      const updateData = { content: 'Updated content' };
      await notesService.updateNote(mockUserId, mockNoteId, updateData);

      expect(mockNote.update).toHaveBeenCalledWith({ content: 'Updated content' });
    });

    it('should update both title and content', async () => {
      const updateData = { title: 'New Title', content: 'New content' };
      await notesService.updateNote(mockUserId, mockNoteId, updateData);

      expect(mockNote.update).toHaveBeenCalledWith({
        title: 'New Title',
        content: 'New content'
      });
    });

    it('should reject empty update data', async () => {
      await expect(notesService.updateNote(mockUserId, mockNoteId, {}))
        .rejects.toThrow('At least one field (title or content) must be provided for update');
    });

    it('should reject invalid note ID', async () => {
      await expect(notesService.updateNote(mockUserId, 'invalid-id', { title: 'New' }))
        .rejects.toThrow('Invalid note ID format');
    });

    it('should reject malicious content', async () => {
      const maliciousData = { title: '<script>alert("xss")</script>' };

      await expect(notesService.updateNote(mockUserId, mockNoteId, maliciousData))
        .rejects.toThrow('Note title contains potentially harmful content');
    });

    it('should handle note not found', async () => {
      Note.findByIdAndUserId.mockResolvedValue(null);

      await expect(notesService.updateNote(mockUserId, mockNoteId, { title: 'New' }))
        .rejects.toThrow('Note not found or access denied');
    });

    it('should trim whitespace from updates', async () => {
      const updateData = { title: '  Trimmed Title  ', content: '  Trimmed content  ' };
      await notesService.updateNote(mockUserId, mockNoteId, updateData);

      expect(mockNote.update).toHaveBeenCalledWith({
        title: 'Trimmed Title',
        content: 'Trimmed content'
      });
    });

    it('should log data modification', async () => {
      const updateData = { title: 'Updated Title' };
      await notesService.updateNote(mockUserId, mockNoteId, updateData);

      expect(logger.security.dataModification).toHaveBeenCalledWith({
        action: 'note_updated',
        userId: mockUserId,
        resource: 'note',
        resourceId: mockNoteId,
        changes: ['title'],
        metadata: {
          titleLength: 13
        }
      });
    });
  });

  describe('deleteNote', () => {
    const mockUserId = 'user-123';
    const mockNoteId = '550e8400-e29b-41d4-a716-446655440000';
    const mockNote = {
      id: mockNoteId,
      delete: jest.fn()
    };

    beforeEach(() => {
      Note.findByIdAndUserId.mockResolvedValue(mockNote);
      mockNote.delete.mockResolvedValue(mockNote);
    });

    it('should delete note successfully', async () => {
      const result = await notesService.deleteNote(mockUserId, mockNoteId);

      expect(Note.findByIdAndUserId).toHaveBeenCalledWith(mockNoteId, mockUserId);
      expect(mockNote.delete).toHaveBeenCalled();
      expect(result).toEqual({
        success: true,
        message: 'Note deleted successfully',
        noteId: mockNoteId
      });
      expect(logger.security.dataModification).toHaveBeenCalledWith({
        action: 'note_deleted',
        userId: mockUserId,
        resource: 'note',
        resourceId: mockNoteId,
        metadata: {
          deletionType: 'soft_delete'
        }
      });
    });

    it('should reject invalid note ID', async () => {
      await expect(notesService.deleteNote(mockUserId, 'invalid-id'))
        .rejects.toThrow('Invalid note ID format');
    });

    it('should handle note not found', async () => {
      Note.findByIdAndUserId.mockResolvedValue(null);

      await expect(notesService.deleteNote(mockUserId, mockNoteId))
        .rejects.toThrow('Note not found or access denied');
    });

    it('should handle database errors', async () => {
      mockNote.delete.mockRejectedValue(new Error('Database error'));

      await expect(notesService.deleteNote(mockUserId, mockNoteId))
        .rejects.toThrow('Failed to delete note. Please try again.');
    });
  });

  describe('searchNotes', () => {
    const mockUserId = 'user-123';
    const mockSearchResults = [
      {
        id: 'note-1',
        title: 'Matching Note',
        content: 'This contains the search term',
        createdAt: new Date(),
        updatedAt: new Date()
      }
    ];

    beforeEach(() => {
      Note.searchByUserId.mockResolvedValue(mockSearchResults);
    });

    it('should search notes successfully', async () => {
      const result = await notesService.searchNotes(mockUserId, 'search term');

      expect(Note.searchByUserId).toHaveBeenCalledWith(mockUserId, 'search term', {
        limit: 10,
        offset: 0
      });
      expect(result.notes).toHaveLength(1);
      expect(result.searchTerm).toBe('search term');
    });

    it('should reject empty search term', async () => {
      await expect(notesService.searchNotes(mockUserId, ''))
        .rejects.toThrow('Search term is required and must be a string');
    });

    it('should reject short search term', async () => {
      await expect(notesService.searchNotes(mockUserId, 'a'))
        .rejects.toThrow('Search term must be at least 2 characters long');
    });

    it('should reject long search term', async () => {
      const longTerm = 'a'.repeat(101);
      await expect(notesService.searchNotes(mockUserId, longTerm))
        .rejects.toThrow('Search term is too long (maximum 100 characters)');
    });

    it('should trim search term', async () => {
      await notesService.searchNotes(mockUserId, '  search term  ');

      expect(Note.searchByUserId).toHaveBeenCalledWith(mockUserId, 'search term', expect.any(Object));
    });

    it('should log search activity', async () => {
      await notesService.searchNotes(mockUserId, 'search term');

      expect(logger.security.dataAccess).toHaveBeenCalledWith({
        action: 'notes_searched',
        userId: mockUserId,
        resource: 'note',
        resultCount: 1,
        searchTermLength: 11,
        pagination: { page: 1, limit: 10 }
      });
    });
  });

  describe('Security Tests', () => {
    const mockUserId = 'user-123';

    describe('XSS Prevention', () => {
      const xssPayloads = [
        '<script>alert("xss")</script>',
        '<img src="x" onerror="alert(1)">',
        'javascript:alert("xss")',
        '<svg onload="alert(1)">',
        '<iframe src="javascript:alert(1)"></iframe>'
      ];

      xssPayloads.forEach(payload => {
        it(`should reject XSS payload in title: ${payload}`, async () => {
          await expect(notesService.createNote(mockUserId, {
            title: payload,
            content: 'Safe content'
          })).rejects.toThrow('Note title contains potentially harmful content');
        });

        it(`should reject XSS payload in content: ${payload}`, async () => {
          await expect(notesService.createNote(mockUserId, {
            title: 'Safe title',
            content: payload
          })).rejects.toThrow('Note content contains potentially harmful content');
        });
      });
    });

    describe('Authorization Tests', () => {
      const mockNoteId = '550e8400-e29b-41d4-a716-446655440000';
      const otherUserId = 'other-user-456';

      it('should prevent access to other user\'s notes', async () => {
        Note.findByIdAndUserId.mockResolvedValue(null);

        await expect(notesService.getNote(otherUserId, mockNoteId))
          .rejects.toThrow('Note not found or access denied');
      });

      it('should prevent updating other user\'s notes', async () => {
        Note.findByIdAndUserId.mockResolvedValue(null);

        await expect(notesService.updateNote(otherUserId, mockNoteId, { title: 'Hacked' }))
          .rejects.toThrow('Note not found or access denied');
      });

      it('should prevent deleting other user\'s notes', async () => {
        Note.findByIdAndUserId.mockResolvedValue(null);

        await expect(notesService.deleteNote(otherUserId, mockNoteId))
          .rejects.toThrow('Note not found or access denied');
      });
    });

    describe('Input Validation', () => {
      it('should validate UUID format for note IDs', async () => {
        const invalidIds = [
          'not-a-uuid',
          '123',
          'abc-def-ghi',
          '550e8400-e29b-41d4-a716-44665544000', // too short
          '550e8400-e29b-41d4-a716-4466554400000' // too long
        ];

        for (const invalidId of invalidIds) {
          await expect(notesService.getNote(mockUserId, invalidId))
            .rejects.toThrow('Invalid note ID format');
        }
      });

      it('should enforce content length limits', async () => {
        const longContent = 'a'.repeat(10001);
        
        await expect(notesService.createNote(mockUserId, {
          title: 'Valid title',
          content: longContent
        })).rejects.toThrow('Note content cannot exceed 10000 characters');
      });

      it('should enforce title length limits', async () => {
        const longTitle = 'a'.repeat(201);
        
        await expect(notesService.createNote(mockUserId, {
          title: longTitle,
          content: 'Valid content'
        })).rejects.toThrow('Note title cannot exceed 200 characters');
      });
    });
  });

  describe('getNoteStats', () => {
    const mockUserId = 'user-123';

    it('should return note statistics', async () => {
      Note.getCountByUserId
        .mockResolvedValueOnce(15) // active notes
        .mockResolvedValueOnce(20); // total including deleted

      const result = await notesService.getNoteStats(mockUserId);

      expect(result).toEqual({
        totalNotes: 15,
        deletedNotes: 5,
        maxNotesAllowed: 1000,
        remainingNotes: 985
      });
    });

    it('should log stats access', async () => {
      Note.getCountByUserId
        .mockResolvedValueOnce(10)
        .mockResolvedValueOnce(12);

      await notesService.getNoteStats(mockUserId);

      expect(logger.security.dataAccess).toHaveBeenCalledWith({
        action: 'note_stats_retrieved',
        userId: mockUserId,
        resource: 'note',
        metadata: {
          totalNotes: 10,
          deletedNotes: 2
        }
      });
    });
  });
});