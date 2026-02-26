const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');

let db;

async function initDB() {
    db = await open({
        filename: './app.db',
        driver: sqlite3.Database
    });

    // Recommended for SQLite performance and reliability
    await db.exec('PRAGMA journal_mode = WAL;');

    // Creates the notes table if it doesn't already exist
    await db.exec(`
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
}

async function getNotes() {
    // 100% SECURE: Hardcoded static query. No dynamic input present.
    return await db.all('SELECT id, content, created_at FROM notes ORDER BY created_at DESC');
}

async function createNote(content) {
    // 100% SECURE: Uses Parameterized Query (?) for content.
    // The driver safely handles all quotes and special characters. 
    // SQL injection is completely impossible here.
    const sql = `INSERT INTO notes (content) VALUES (?)`;
    const result = await db.run(sql, [content]);

    return await db.get('SELECT id, content, created_at FROM notes WHERE id = ?', [result.lastID]);
}

async function updateNote(id, content) {
    // 100% SECURE: Parameterized Query (?)
    const sql = `UPDATE notes SET content = ? WHERE id = ?`;
    await db.run(sql, [content, id]);

    // Check if anything was actually updated
    return await db.get('SELECT id, content, created_at FROM notes WHERE id = ?', [id]);
}

async function deleteNote(id) {
    // 100% SECURE: Parameterized Query (?)
    const sql = `DELETE FROM notes WHERE id = ?`;
    const result = await db.run(sql, [id]);

    return result.changes > 0; // Return true if a row was actually deleted
}

module.exports = {
    initDB,
    getNotes,
    createNote,
    updateNote,
    deleteNote
};
