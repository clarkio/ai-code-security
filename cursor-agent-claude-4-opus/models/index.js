const sequelize = require('../config/database');
const User = require('./User');
const Note = require('./Note');

// Define associations
User.hasMany(Note, {
  foreignKey: 'user_id',
  as: 'notes',
  onDelete: 'CASCADE',
  onUpdate: 'CASCADE'
});

Note.belongsTo(User, {
  foreignKey: 'user_id',
  as: 'author',
  onDelete: 'CASCADE',
  onUpdate: 'CASCADE'
});

// Sync database
const syncDatabase = async () => {
  try {
    await sequelize.sync({ alter: process.env.NODE_ENV !== 'production' });
    console.log('Database synchronized successfully');
  } catch (error) {
    console.error('Error synchronizing database:', error);
    process.exit(1);
  }
};

module.exports = {
  sequelize,
  User,
  Note,
  syncDatabase
};