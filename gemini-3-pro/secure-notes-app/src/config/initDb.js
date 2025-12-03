const db = require("./database");

const initDb = () => {
  db.serialize(() => {
    // Users table
    db.run(
      `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )`,
      (err) => {
        if (err) {
          console.error("Error creating users table:", err.message);
        } else {
          console.log("Users table created or already exists.");
        }
      }
    );

    // Notes table
    db.run(
      `CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`,
      (err) => {
        if (err) {
          console.error("Error creating notes table:", err.message);
        } else {
          console.log("Notes table created or already exists.");
        }
      }
    );
  });
};

initDb();
