const notesService = require('../services/notesService');
const encryptionService = require('../services/encryptionService');
const Note = require('../models/Note');

// Load test environment
require('./setup');

// Mock dependencies
jest.mock('../utils/logger', () => ({
  warn: jest.fn(),
  error: jest.fn(),
  info: jest.fn(),
  security: {
    dataAccess: jest.fn(),
    dataModification: jest.fn()
  }
}));

jest.mock('../models/Note');

describe('Authorization and Data Protection Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Unauthorized Note Access Prevention', () => {
    test('should prevent users from accessing notes they do not own', async () => {
      const userId1 = 'user-123';
      const userId2 = 'user-456';
      const noteId = '550e8400-e29b-41d4-a716-446655440000';

      // Mock note not found for unauthorized user
      Note.findByIdAndUserId.mockResolvedValue(null);

      try {
        await notesService.getNote(userId2, noteId);
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error.message).toContain('Note not found or access denied');
      }

      // Verify the correct parameters were used for authorization check
      expect(Note.findByIdAndUserId).toHaveBeenCalledWith(noteId, userId2);
    });

    test('should prevent users from updating notes they do not own', async () => {
      const userId1 = 'user-123';
      const userId2 = 'user-456';
      const noteId = '550e8400-e29b-41d4-a716-446655440001';

      // Mock note not found for unauthorized user
      Note.findByIdAndUserId.mockResolvedValue(null);

      try {
        await notesService.updateNote(userId2, noteId, {
          title: 'Malicious Update',
          content: 'Trying to update someone else\'s note'
        });
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error.message).toContain('Note not found or access denied');
      }

      expect(Note.findByIdAndUserId).toHaveBeenCalledWith(noteId, userId2);
    });

    test('should prevent users from deleting notes they do not own', async () => {
      const userId1 = 'user-123';
      const userId2 = 'user-456';
      const noteId = '550e8400-e29b-41d4-a716-446655440002';

      // Mock note not found for unauthorized user
      Note.findByIdAndUserId.mockResolvedValue(null);

      try {
        await notesService.deleteNote(userId2, noteId);
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error.message).toContain('Note not found or access denied');
      }

      expect(Note.findByIdAndUserId).toHaveBeenCalledWith(noteId, userId2);
    });

    test('should only return notes belonging to the authenticated user', async () => {
      const userId = 'user-123';
      const mockNotes = [
        {
          id: '550e8400-e29b-41d4-a716-446655440003',
          userId: userId,
          title: 'User 123 Note 1',
          content: 'Content 1',
          createdAt: new Date(),
          updatedAt: new Date(),
          isDeleted: false
        },
        {
          id: '550e8400-e29b-41d4-a716-446655440004',
          userId: userId,
          title: 'User 123 Note 2',
          content: 'Content 2',
          createdAt: new Date(),
          updatedAt: new Date(),
          isDeleted: false
        }
      ];

      Note.findByUserId.mockResolvedValue(mockNotes);
      Note.getCountByUserId.mockResolvedValue(2);

      const result = await notesService.getNotes(userId);

      expect(result.notes).toHaveLength(2);
      expect(Note.findByUserId).toHaveBeenCalledWith(userId, expect.any(Object));
      
      // Verify all returned notes belong to the user
      result.notes.forEach(note => {
        expect(mockNotes.find(n => n.id === note.id)).toBeDefined();
      });
    });

    test('should prevent privilege escalation through parameter manipulation', async () => {
      const regularUserId = 'user-123';
      const adminUserId = 'admin-456';
      const noteId = '550e8400-e29b-41d4-a716-446655440005';

      // Mock note belonging to admin user
      const adminNote = {
        id: noteId,
        userId: adminUserId,
        title: 'Admin Secret Note',
        content: 'Confidential admin information',
        createdAt: new Date(),
        updatedAt: new Date()
      };

      // Regular user tries to access admin note - should fail
      Note.findByIdAndUserId.mockResolvedValue(null);

      try {
        await notesService.getNote(regularUserId, noteId);
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error.message).toContain('Note not found or access denied');
      }

      // Verify authorization check used regular user ID, not admin ID
      expect(Note.findByIdAndUserId).toHaveBeenCalledWith(noteId, regularUserId);
    });

    test('should prevent access to soft-deleted notes by default', async () => {
      const userId = 'user-123';
      const mockNotes = [
        {
          id: '550e8400-e29b-41d4-a716-446655440006',
          userId: userId,
          title: 'Active Note',
          content: 'Active content',
          createdAt: new Date(),
          updatedAt: new Date(),
          isDeleted: false
        }
        // Soft-deleted notes should not be returned by default
      ];

      Note.findByUserId.mockResolvedValue(mockNotes);
      Note.getCountByUserId.mockResolvedValue(1);

      const result = await notesService.getNotes(userId);

      expect(result.notes).toHaveLength(1);
      expect(result.notes[0].isDeleted).toBe(false);
      
      // Verify includeDeleted was false by default
      expect(Note.findByUserId).toHaveBeenCalledWith(userId, 
        expect.objectContaining({ includeDeleted: false })
      );
    });
  });

  describe('Encryption and Decryption Validation', () => {
    test('should encrypt data with unique IVs for each operation', () => {
      const plaintext = 'Sensitive note content';
      
      const encrypted1 = encryptionService.encrypt(plaintext);
      const encrypted2 = encryptionService.encrypt(plaintext);
      
      // Same plaintext should produce different encrypted results due to unique IVs
      expect(encrypted1).not.toBe(encrypted2);
      
      // Both should decrypt to the same plaintext
      expect(encryptionService.decrypt(encrypted1)).toBe(plaintext);
      expect(encryptionService.decrypt(encrypted2)).toBe(plaintext);
      
      // Verify IV uniqueness by parsing the encrypted data
      const data1 = JSON.parse(encrypted1);
      const data2 = JSON.parse(encrypted2);
      expect(data1.iv).not.toBe(data2.iv);
    });

    test('should reject invalid encrypted data formats', () => {
      const invalidFormats = [
        '', // Empty string
        'not-json', // Invalid JSON
        '{}', // Empty object
        '{"iv":"abc"}', // Missing required fields
        '{"iv":"abc","tag":"def"}', // Missing encrypted field
        '{"iv":"abc","encrypted":"def"}', // Missing tag field
        '{"tag":"abc","encrypted":"def"}', // Missing IV field
      ];

      for (const invalidData of invalidFormats) {
        expect(() => {
          encryptionService.decrypt(invalidData);
        }).toThrow();
      }
    });

    test('should detect tampering with encrypted data', () => {
      const plaintext = 'Original sensitive data';
      const encrypted = encryptionService.encrypt(plaintext);
      
      // Verify original decryption works
      expect(encryptionService.decrypt(encrypted)).toBe(plaintext);
      
      // Parse and tamper with the encrypted data
      const data = JSON.parse(encrypted);
      
      // Test tampering with auth tag - change last character
      const originalTag = data.tag;
      const lastChar = originalTag.slice(-1);
      const newChar = lastChar === 'a' ? 'b' : 'a';
      const tamperedTag = originalTag.slice(0, -1) + newChar;
      
      const tamperedData = { ...data, tag: tamperedTag };
      const tamperedEncrypted = JSON.stringify(tamperedData);
      
      // This should throw an error due to authentication failure
      let threwError = false;
      try {
        encryptionService.decrypt(tamperedEncrypted);
      } catch (error) {
        threwError = true;
      }
      
      expect(threwError).toBe(true);
    });

    test('should use authenticated encryption (GCM mode)', () => {
      const plaintext = 'Test data for authentication';
      const encrypted = encryptionService.encrypt(plaintext);
      const data = JSON.parse(encrypted);
      
      // Verify that authentication tag is present
      expect(data.tag).toBeDefined();
      expect(data.tag).toHaveLength(32); // 16 bytes = 32 hex chars
      
      // Verify that tampering with tag fails decryption
      const tamperedData = { ...data, tag: '0'.repeat(32) };
      const tamperedEncrypted = JSON.stringify(tamperedData);
      
      expect(() => {
        encryptionService.decrypt(tamperedEncrypted);
      }).toThrow();
    });

    test('should handle key rotation properly', () => {
      // This test assumes rotation key is available
      if (!encryptionService.rotationKey) {
        // Skip test if rotation key not configured
        return;
      }

      const plaintext = 'Data for key rotation test';
      
      // Encrypt with primary key
      const encryptedV1 = encryptionService.encrypt(plaintext);
      const dataV1 = JSON.parse(encryptedV1);
      expect(dataV1.keyVersion).toBe(1);
      
      // Encrypt with rotation key
      const encryptedV2 = encryptionService.encryptWithRotationKey(plaintext);
      const dataV2 = JSON.parse(encryptedV2);
      expect(dataV2.keyVersion).toBe(2);
      
      // Both should decrypt correctly
      expect(encryptionService.decrypt(encryptedV1)).toBe(plaintext);
      expect(encryptionService.decrypt(encryptedV2)).toBe(plaintext);
      
      // Re-encryption should work
      const reencrypted = encryptionService.reencrypt(encryptedV1);
      expect(encryptionService.decrypt(reencrypted)).toBe(plaintext);
    });

    test('should validate input data types for encryption', () => {
      const invalidInputs = [
        null,
        undefined,
        123,
        {},
        [],
        true,
        ''
      ];

      for (const invalidInput of invalidInputs) {
        expect(() => {
          encryptionService.encrypt(invalidInput);
        }).toThrow('Plaintext must be a non-empty string');
      }
    });

    test('should validate input data types for decryption', () => {
      const invalidInputs = [
        null,
        undefined,
        123,
        {},
        [],
        true,
        ''
      ];

      for (const invalidInput of invalidInputs) {
        expect(() => {
          encryptionService.decrypt(invalidInput);
        }).toThrow('Encrypted data must be a non-empty string');
      }
    });
  });

  describe('Data Leakage Prevention', () => {
    test('should not expose sensitive data in error messages', async () => {
      const userId = 'user-123';
      const sensitiveNoteId = '550e8400-e29b-41d4-a716-446655440007';

      // Mock database error
      Note.findByIdAndUserId.mockRejectedValue(new Error('Database connection failed'));

      try {
        await notesService.getNote(userId, sensitiveNoteId);
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        // Error message should be generic, not expose internal details
        expect(error.message).toBe('Failed to retrieve note. Please try again.');
        expect(error.message).not.toContain('Database connection failed');
        expect(error.message).not.toContain(sensitiveNoteId);
      }
    });

    test('should sanitize note content to prevent XSS', async () => {
      const userId = 'user-123';
      const maliciousContent = {
        title: '<script>alert("XSS")</script>Malicious Title',
        content: '<img src="x" onerror="alert(\'XSS\')">'
      };

      try {
        await notesService.createNote(userId, maliciousContent);
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error.message).toContain('potentially harmful content');
      }
    });

    test('should prevent SQL injection through note content', async () => {
      const userId = 'user-123';
      const sqlInjectionAttempts = [
        {
          title: "'; DROP TABLE notes; --",
          content: 'Normal content'
        },
        {
          title: 'Normal title',
          content: "' UNION SELECT * FROM users --"
        },
        {
          title: '1\' OR \'1\'=\'1',
          content: 'Normal content'
        }
      ];

      // Mock successful note creation (SQL injection should be prevented at model level)
      const mockNote = {
        id: 'note-123',
        title: 'Sanitized title',
        content: 'Sanitized content',
        createdAt: new Date(),
        updatedAt: new Date()
      };

      Note.create.mockResolvedValue(mockNote);
      Note.getCountByUserId.mockResolvedValue(0);

      for (const maliciousNote of sqlInjectionAttempts) {
        // The service should either sanitize or reject the content
        // If it passes validation, the model layer should handle SQL injection prevention
        try {
          const result = await notesService.createNote(userId, maliciousNote);
          // If creation succeeds, verify the content was sanitized
          expect(result.title).not.toContain('DROP TABLE');
          expect(result.title).not.toContain('UNION SELECT');
          expect(result.content).not.toContain('DROP TABLE');
          expect(result.content).not.toContain('UNION SELECT');
        } catch (error) {
          // If validation rejects it, that's also acceptable
          expect(error.message).toContain('harmful content');
        }
      }
    });

    test('should limit note content length to prevent DoS attacks', async () => {
      const userId = 'user-123';
      const maxLength = notesService.maxContentLength;
      
      const oversizedNote = {
        title: 'Normal title',
        content: 'x'.repeat(maxLength + 1)
      };

      try {
        await notesService.createNote(userId, oversizedNote);
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error.message).toContain(`cannot exceed ${maxLength} characters`);
      }
    });

    test('should limit number of notes per user', async () => {
      const userId = 'user-123';
      const maxNotes = notesService.maxNotesPerUser;

      // Mock user already at limit
      Note.getCountByUserId.mockResolvedValue(maxNotes);

      try {
        await notesService.createNote(userId, {
          title: 'One too many',
          content: 'This should fail'
        });
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error.message).toContain(`Maximum number of notes (${maxNotes}) reached`);
      }
    });

    test('should prevent information disclosure through timing attacks', async () => {
      const userId = 'user-123';
      const existingNoteId = '550e8400-e29b-41d4-a716-446655440008';
      const nonExistentNoteId = '550e8400-e29b-41d4-a716-446655440009';

      // Mock existing note
      Note.findByIdAndUserId
        .mockResolvedValueOnce(null) // First call - non-existent note
        .mockResolvedValueOnce(null); // Second call - existing note but wrong user

      // Measure timing for non-existent note
      const start1 = Date.now();
      try {
        await notesService.getNote(userId, nonExistentNoteId);
      } catch (error) {
        // Expected to fail
      }
      const time1 = Date.now() - start1;

      // Measure timing for existing note (but wrong user)
      const start2 = Date.now();
      try {
        await notesService.getNote(userId, existingNoteId);
      } catch (error) {
        // Expected to fail
      }
      const time2 = Date.now() - start2;

      // Both should return the same error message
      // Timing difference should be minimal (within reasonable variance)
      const timeDifference = Math.abs(time1 - time2);
      expect(timeDifference).toBeLessThan(50); // Allow 50ms variance
    });
  });

  describe('Privilege Escalation Prevention', () => {
    test('should prevent horizontal privilege escalation', async () => {
      const user1Id = 'user-123';
      const user2Id = 'user-456';
      const user2NoteId = '550e8400-e29b-41d4-a716-446655440010';

      // User 1 tries to access User 2's note
      Note.findByIdAndUserId.mockResolvedValue(null);

      try {
        await notesService.getNote(user1Id, user2NoteId);
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error.message).toContain('Note not found or access denied');
      }

      // Verify the authorization check used the correct user ID
      expect(Note.findByIdAndUserId).toHaveBeenCalledWith(user2NoteId, user1Id);
    });

    test('should prevent vertical privilege escalation through note operations', async () => {
      const regularUserId = 'regular-user-123';
      const adminNoteId = '550e8400-e29b-41d4-a716-446655440011';

      // Regular user tries to access admin note
      Note.findByIdAndUserId.mockResolvedValue(null);

      try {
        await notesService.updateNote(regularUserId, adminNoteId, {
          title: 'Trying to escalate privileges',
          content: 'This should not work'
        });
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error.message).toContain('Note not found or access denied');
      }

      expect(Note.findByIdAndUserId).toHaveBeenCalledWith(adminNoteId, regularUserId);
    });

    test('should validate user ownership for all CRUD operations', async () => {
      const userId = 'user-123';
      const noteId = '550e8400-e29b-41d4-a716-446655440012';

      // Mock note not found for all operations
      Note.findByIdAndUserId.mockResolvedValue(null);

      const operations = [
        () => notesService.getNote(userId, noteId),
        () => notesService.updateNote(userId, noteId, { title: 'Updated' }),
        () => notesService.deleteNote(userId, noteId)
      ];

      for (const operation of operations) {
        try {
          await operation();
          expect(true).toBe(false); // Should not reach here
        } catch (error) {
          expect(error.message).toContain('Note not found or access denied');
        }
      }

      // Verify ownership check was called for each operation
      expect(Note.findByIdAndUserId).toHaveBeenCalledTimes(3);
    });

    test('should prevent batch operations on unauthorized notes', async () => {
      const userId = 'user-123';
      const unauthorizedNoteIds = [
        '550e8400-e29b-41d4-a716-446655440013',
        '550e8400-e29b-41d4-a716-446655440014', 
        '550e8400-e29b-41d4-a716-446655440015'
      ];

      // Mock all notes as not found/unauthorized
      Note.findByIdAndUserId.mockResolvedValue(null);

      // Attempt to access multiple unauthorized notes
      for (const noteId of unauthorizedNoteIds) {
        try {
          await notesService.getNote(userId, noteId);
          expect(true).toBe(false); // Should not reach here
        } catch (error) {
          expect(error.message).toContain('Note not found or access denied');
        }
      }

      // Verify each note was checked individually
      expect(Note.findByIdAndUserId).toHaveBeenCalledTimes(unauthorizedNoteIds.length);
    });

    test('should prevent parameter pollution attacks', async () => {
      const userId = 'user-123';
      const noteId = '550e8400-e29b-41d4-a716-446655440016';

      // Mock successful note retrieval
      const mockNote = {
        id: noteId,
        userId: userId,
        title: 'Test Note',
        content: 'Test Content',
        createdAt: new Date(),
        updatedAt: new Date(),
        update: jest.fn().mockResolvedValue({
          id: noteId,
          title: 'Updated Title',
          content: 'Test Content',
          createdAt: new Date(),
          updatedAt: new Date()
        })
      };

      Note.findByIdAndUserId.mockResolvedValue(mockNote);

      // Attempt parameter pollution with array values
      const maliciousUpdate = {
        title: ['Legitimate Title', 'Malicious Title'],
        content: 'Normal content'
      };

      try {
        await notesService.updateNote(userId, noteId, maliciousUpdate);
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        // Should reject non-string title
        expect(error.message).toContain('must be a string');
      }
    });
  });
});