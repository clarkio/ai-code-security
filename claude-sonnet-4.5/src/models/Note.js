/**
 * Note Model
 * In-memory storage for demonstration
 * In production, use a proper database with encryption at rest
 */

// In-memory store (use database in production)
const notes = new Map();

class Note {
  /**
   * Create a new note
   */
  static create(noteData) {
    notes.set(noteData.id, noteData);
    return noteData;
  }

  /**
   * Find note by ID
   */
  static findById(id) {
    return notes.get(id);
  }

  /**
   * Find all notes by user ID
   */
  static findByUserId(userId) {
    return Array.from(notes.values()).filter((note) => note.userId === userId);
  }

  /**
   * Update note
   */
  static update(id, updateData) {
    const note = notes.get(id);
    if (note) {
      const updatedNote = { ...note, ...updateData };
      notes.set(id, updatedNote);
      return updatedNote;
    }
    return null;
  }

  /**
   * Delete note
   */
  static delete(id) {
    return notes.delete(id);
  }

  /**
   * Delete all notes by user ID
   */
  static deleteByUserId(userId) {
    const userNotes = this.findByUserId(userId);
    userNotes.forEach((note) => notes.delete(note.id));
    return userNotes.length;
  }
}

module.exports = Note;
