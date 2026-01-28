/**
 * Unit Tests for Notes Model
 */
const NotesModel = require('../src/models/note');
const db = require('../src/models/database');

// Mock database
jest.mock('../src/models/database', () => ({
  run: jest.fn(),
  get: jest.fn(),
  query: jest.fn(),
  initialize: jest.fn(),
  close: jest.fn()
}));

// Mock logger
jest.mock('../src/utils/logger', () => ({
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  securityEvent: jest.fn()
}));

describe('NotesModel', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  const mockUserId = '123e4567-e89b-12d3-a456-426614174000';
  const mockNoteId = '123e4567-e89b-12d3-a456-426614174001';

  describe('create', () => {
    it('should create a note successfully', () => {
      const mockNote = {
        id: mockNoteId,
        user_id: mockUserId,
        title: 'Test Note',
        content: 'Test Content',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };

      db.run.mockReturnValue({ changes: 1 });
      db.get.mockReturnValue(mockNote);

      const result = NotesModel.create(mockUserId, 'Test Note', 'Test Content');

      expect(db.run).toHaveBeenCalled();
      expect(result).toBeDefined();
      expect(result.title).toBe('Test Note');
    });

    it('should reject empty title', () => {
      expect(() => {
        NotesModel.create(mockUserId, '', 'Content');
      }).toThrow('Title is required');
    });

    it('should reject too long title', () => {
      const longTitle = 'a'.repeat(300);
      expect(() => {
        NotesModel.create(mockUserId, longTitle, 'Content');
      }).toThrow('Title must be less than');
    });

    it('should reject XSS in title', () => {
      expect(() => {
        NotesModel.create(mockUserId, '<script>alert(1)</script>', 'Content');
      }).toThrow('contains invalid characters');
    });
  });

  describe('getById', () => {
    it('should return note for valid owner', () => {
      const mockNote = {
        id: mockNoteId,
        title: 'Test Note',
        content: 'Test Content'
      };

      db.get.mockReturnValue(mockNote);

      const result = NotesModel.getById(mockNoteId, mockUserId);

      expect(result).toEqual(mockNote);
    });

    it('should reject invalid UUID format', () => {
      expect(() => {
        NotesModel.getById('invalid-uuid', mockUserId);
      }).toThrow('Invalid note ID format');
    });

    it('should return null for non-existent note', () => {
      db.get.mockReturnValue(null);

      const result = NotesModel.getById(mockNoteId, mockUserId);

      expect(result).toBeNull();
    });
  });

  describe('update', () => {
    it('should update note successfully', () => {
      const updatedNote = {
        id: mockNoteId,
        title: 'Updated Title',
        content: 'Updated Content'
      };

      db.get
        .mockReturnValueOnce({ id: mockNoteId }) // For ownership check
        .mockReturnValueOnce(updatedNote); // For getById

      const result = NotesModel.update(mockNoteId, mockUserId, {
        title: 'Updated Title',
        content: 'Updated Content'
      });

      expect(result).toEqual(updatedNote);
    });

    it('should reject update for non-owned note', () => {
      db.get.mockReturnValue(null);

      expect(() => {
        NotesModel.update(mockNoteId, 'other-user-id', { title: 'New Title' });
      }).toThrow('Note not found or access denied');
    });

    it('should reject XSS in update', () => {
      db.get.mockReturnValue({ id: mockNoteId });

      expect(() => {
        NotesModel.update(mockNoteId, mockUserId, {
          title: '<script>alert(1)</script>'
        });
      }).toThrow('contains invalid characters');
    });
  });

  describe('delete', () => {
    it('should delete note successfully', () => {
      db.get.mockReturnValue({ id: mockNoteId });
      db.run.mockReturnValue({ changes: 1 });

      const result = NotesModel.delete(mockNoteId, mockUserId);

      expect(result).toBe(true);
    });

    it('should reject delete for non-owned note', () => {
      db.get.mockReturnValue(null);

      expect(() => {
        NotesModel.delete(mockNoteId, 'other-user-id');
      }).toThrow('Note not found or access denied');
    });
  });
});
