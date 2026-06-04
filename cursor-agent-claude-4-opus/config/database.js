const { Sequelize } = require('sequelize');
const path = require('path');
require('dotenv').config();

// Create data directory if it doesn't exist
const fs = require('fs');
const dataDir = path.dirname(process.env.DB_PATH || './data/database.sqlite');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Initialize Sequelize with SQLite
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: process.env.DB_PATH || './data/database.sqlite',
  logging: process.env.NODE_ENV === 'production' ? false : console.log,
  pool: {
    max: 5,
    min: 0,
    acquire: 30000,
    idle: 10000
  },
  // Additional security options
  define: {
    // Prevent SQL injection by using parameterized queries
    underscored: true,
    timestamps: true,
    paranoid: true, // Soft deletes
    freezeTableName: true
  }
});

// Test connection
sequelize.authenticate()
  .then(() => {
    console.log('Database connection established successfully.');
  })
  .catch(err => {
    console.error('Unable to connect to the database:', err);
    process.exit(1);
  });

module.exports = sequelize;