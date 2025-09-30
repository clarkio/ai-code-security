/**
 * User Model
 * In-memory storage for demonstration
 * In production, use a proper database with encryption at rest
 */

// In-memory store (use database in production)
const users = new Map();

class User {
  /**
   * Create a new user
   */
  static create(userData) {
    users.set(userData.id, userData);
    return userData;
  }

  /**
   * Find user by ID
   */
  static findById(id) {
    return users.get(id);
  }

  /**
   * Find user by username
   */
  static findByUsername(username) {
    return Array.from(users.values()).find(
      (user) => user.username.toLowerCase() === username.toLowerCase()
    );
  }

  /**
   * Update last login
   */
  static updateLastLogin(id) {
    const user = users.get(id);
    if (user) {
      user.lastLogin = new Date().toISOString();
      users.set(id, user);
    }
    return user;
  }

  /**
   * Delete user
   */
  static delete(id) {
    return users.delete(id);
  }

  /**
   * Get all users (admin only - not exposed via API)
   */
  static findAll() {
    return Array.from(users.values());
  }
}

module.exports = User;
