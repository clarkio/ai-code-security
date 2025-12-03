const sqlite3 = require("sqlite3").verbose();
const path = require("path");
require("dotenv").config();

const dbPath = process.env.DB_PATH || "./notes.db";

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error("Error opening database " + dbPath + ": " + err.message);
  } else {
    console.log("Connected to the SQLite database.");
  }
});

module.exports = db;
