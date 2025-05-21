// google-jules/tests/testSetup.js
const db = require('../config/database'); // Ensure this points to the in-memory DB for tests

const createTables = () => {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            // Use db.exec for multiple statements for simplicity if needed, but db.run is fine.
            // Ensure foreign key support is enabled (already in config/database.js)
            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`, (errUsers) => {
                if (errUsers) {
                    console.error('Error creating users table:', errUsers.message);
                    return reject(errUsers);
                }
                console.log('Users table created or already exists.');
                db.run(`CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )`, (errNotes) => {
                    if (errNotes) {
                        console.error('Error creating notes table:', errNotes.message);
                        return reject(errNotes);
                    }
                    console.log('Notes table created or already exists.');
                    resolve(); // Resolve after both tables are ensured
                });
            });
        });
    });
};

const clearTables = () => {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            db.run("DELETE FROM notes", (err) => { if (err) return reject(err); });
            db.run("DELETE FROM users", (err) => { if (err) return reject(err); });
            db.run("DELETE FROM sqlite_sequence WHERE name='users' OR name='notes'", (err) => {
                 if (err) return reject(err); 
            });
            resolve();
        });
    });
};

const initializeTestDB = async () => {
    try {
        // console.log('Applying database schema for test environment...');
        await createTables();
        // console.log('Test database schema applied.');
    } catch (error) {
        console.error('Failed to apply test database schema:', error);
        process.exit(1);
    }
};

const clearTestDB = async () => {
    try {
        await clearTables();
    } catch (error) {
        console.error('Failed to clear test database:', error);
    }
};

// Wrapper for Jest's describe to setup and teardown DB for a suite
const describeWithDB = (description, suiteFunction) => {
  describe(description, () => {
    beforeAll(async () => {
      await initializeTestDB();
    });

    beforeEach(async () => {
      await clearTestDB();
    });

    suiteFunction();

    // afterAll(async () => {
      // db.close((err) => {
      //   if (err) console.error('Error closing test database:', err);
      // });
    // });
  });
};

module.exports = { initializeTestDB, clearTestDB, describeWithDB };
