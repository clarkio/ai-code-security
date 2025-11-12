const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

class Note {
  constructor() {
    this.dataFile = path.join(__dirname, '../data/notes.json');
    this.ensureDataDirectory();
    this.notes = this.loadNotes();
  }

  /**
   * Ensure data directory exists
   */
  ensureDataDirectory() {
    const dataDir = path.dirname(this.dataFile);
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
  }

  /**
   * Load notes from file
   */
  loadNotes() {
    try {
      if (fs.existsSync(this.dataFile)) {
        const data = fs.readFileSync(this.dataFile, 'utf8');
        return JSON.parse(data);
      }
      return {};
    } catch (error) {
      logger.error('Error loading notes:', error);
      return {};
    }
  }

  /**
   * Save notes to file
   */
  saveNotes() {
    try {
      fs.writeFileSync(this.dataFile, JSON.stringify(this.notes, null, 2));
      return true;
    } catch (error) {
      logger.error('Error saving notes:', error);
      return false;
    }
  }

  /**
   * Create a new note
   */
  create(noteData) {
    const id = uuidv4();
    const now = new Date().toISOString();
    
    const note = {
      id,
      title: noteData.title,
      content: noteData.content,
      tags: noteData.tags || [],
      createdAt: now,
      updatedAt: now
    };

    this.notes[id] = note;
    
    if (this.saveNotes()) {
      logger.info(`Note created: ${id}`);
      return note;
    } else {
      throw new Error('Failed to save note');
    }
  }

  /**
   * Get all notes
   */
  getAll() {
    return Object.values(this.notes).sort((a, b) => 
      new Date(b.updatedAt) - new Date(a.updatedAt)
    );
  }

  /**
   * Get note by ID
   */
  getById(id) {
    const note = this.notes[id];
    if (note) {
      logger.info(`Note retrieved: ${id}`);
      return note;
    }
    return null;
  }

  /**
   * Update note by ID
   */
  update(id, updateData) {
    const note = this.notes[id];
    if (!note) {
      return null;
    }

    // Update fields
    if (updateData.title !== undefined) {
      note.title = updateData.title;
    }
    if (updateData.content !== undefined) {
      note.content = updateData.content;
    }
    if (updateData.tags !== undefined) {
      note.tags = updateData.tags;
    }

    note.updatedAt = new Date().toISOString();

    this.notes[id] = note;
    
    if (this.saveNotes()) {
      logger.info(`Note updated: ${id}`);
      return note;
    } else {
      throw new Error('Failed to update note');
    }
  }

  /**
   * Delete note by ID
   */
  delete(id) {
    const note = this.notes[id];
    if (!note) {
      return false;
    }

    delete this.notes[id];
    
    if (this.saveNotes()) {
      logger.info(`Note deleted: ${id}`);
      return true;
    } else {
      throw new Error('Failed to delete note');
    }
  }

  /**
   * Search notes by title or content
   */
  search(query) {
    const searchTerm = query.toLowerCase();
    return Object.values(this.notes).filter(note => 
      note.title.toLowerCase().includes(searchTerm) ||
      note.content.toLowerCase().includes(searchTerm) ||
      note.tags.some(tag => tag.toLowerCase().includes(searchTerm))
    ).sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
  }

  /**
   * Get notes by tag
   */
  getByTag(tag) {
    const searchTerm = tag.toLowerCase();
    return Object.values(this.notes).filter(note =>
      note.tags.some(noteTag => noteTag.toLowerCase() === searchTerm)
    ).sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
  }

  /**
   * Get all unique tags
   */
  getAllTags() {
    const allTags = new Set();
    Object.values(this.notes).forEach(note => {
      note.tags.forEach(tag => allTags.add(tag));
    });
    return Array.from(allTags).sort();
  }
}

module.exports = Note;
