const db = require('../config/database');

const Note = {
  createNote: (title, content, userId) => {
    return new Promise((resolve, reject) => {
      const sql = 'INSERT INTO notes (title, content, user_id) VALUES (?, ?, ?)';
      db.run(sql, [title, content, userId], function (err) {
        if (err) {
          reject(err);
        } else {
          // Return the newly created note, including its ID and timestamps
          db.get('SELECT * FROM notes WHERE id = ?', [this.lastID], (err, note) => {
            if (err) {
              reject(err);
            } else {
              resolve(note);
            }
          });
        }
      });
    });
  },

  getNotesByUserId: (userId) => {
    return new Promise((resolve, reject) => {
      const sql = 'SELECT * FROM notes WHERE user_id = ? ORDER BY updated_at DESC';
      db.all(sql, [userId], (err, notes) => {
        if (err) {
          reject(err);
        } else {
          resolve(notes);
        }
      });
    });
  },

  getNoteByIdAndUserId: (noteId, userId) => {
    return new Promise((resolve, reject) => {
      const sql = 'SELECT * FROM notes WHERE id = ? AND user_id = ?';
      db.get(sql, [noteId, userId], (err, note) => {
        if (err) {
          reject(err);
        } else {
          resolve(note); // Returns the note or undefined if not found/not authorized
        }
      });
    });
  },

  updateNoteByIdAndUserId: (noteId, title, content, userId) => {
    return new Promise((resolve, reject) => {
      const sql = `
        UPDATE notes 
        SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE id = ? AND user_id = ?`;
      db.run(sql, [title, content, noteId, userId], function (err) {
        if (err) {
          reject(err);
        } else {
          if (this.changes === 0) {
            // No rows updated, meaning note not found or user not authorized
            resolve(null); 
          } else {
            // Fetch and return the updated note
            db.get('SELECT * FROM notes WHERE id = ? AND user_id = ?', [noteId, userId], (err, note) => {
              if (err) {
                reject(err);
              } else {
                resolve(note);
              }
            });
          }
        }
      });
    });
  },

  deleteNoteByIdAndUserId: (noteId, userId) => {
    return new Promise((resolve, reject) => {
      const sql = 'DELETE FROM notes WHERE id = ? AND user_id = ?';
      db.run(sql, [noteId, userId], function (err) {
        if (err) {
          reject(err);
        } else {
          resolve(this.changes); // Returns the number of rows deleted (0 or 1)
        }
      });
    });
  }
};

module.exports = Note;
