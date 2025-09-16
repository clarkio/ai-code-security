const fs = require('fs').promises;
const path = require('path');
const databaseConnection = require('./connection');
const logger = require('../utils/logger');

class DatabaseMigrator {
  constructor() {
    this.db = databaseConnection;
    this.migrationsPath = path.join(__dirname, 'migrations');
  }

  /**
   * Run all pending migrations
   */
  async migrate() {
    try {
      logger.info('Starting database migration');

      // Ensure database connection is established
      if (!this.db.isConnected) {
        await this.db.initialize();
      }

      // Create migrations table if it doesn't exist
      await this.createMigrationsTable();

      // Get list of migration files
      const migrationFiles = await this.getMigrationFiles();
      
      // Get applied migrations
      const appliedMigrations = await this.getAppliedMigrations();

      // Filter pending migrations
      const pendingMigrations = migrationFiles.filter(
        file => !appliedMigrations.includes(this.getVersionFromFilename(file))
      );

      if (pendingMigrations.length === 0) {
        logger.info('No pending migrations found');
        return { applied: 0, total: migrationFiles.length };
      }

      logger.info(`Found ${pendingMigrations.length} pending migrations`);

      // Apply pending migrations
      let appliedCount = 0;
      for (const migrationFile of pendingMigrations) {
        await this.applyMigration(migrationFile);
        appliedCount++;
      }

      logger.info(`Successfully applied ${appliedCount} migrations`);

      return { applied: appliedCount, total: migrationFiles.length };

    } catch (error) {
      logger.error('Migration failed', {
        error: error.message,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Rollback the last migration (if supported)
   */
  async rollback() {
    try {
      logger.info('Starting migration rollback');

      // Get the last applied migration
      const lastMigration = await this.getLastAppliedMigration();
      
      if (!lastMigration) {
        logger.info('No migrations to rollback');
        return false;
      }

      // Check if rollback file exists
      const rollbackFile = this.getRollbackFilename(lastMigration.version);
      const rollbackPath = path.join(this.migrationsPath, rollbackFile);

      try {
        await fs.access(rollbackPath);
      } catch (error) {
        logger.warn(`No rollback file found for migration ${lastMigration.version}`);
        return false;
      }

      // Apply rollback
      await this.applyRollback(rollbackFile, lastMigration.version);

      logger.info(`Successfully rolled back migration ${lastMigration.version}`);
      return true;

    } catch (error) {
      logger.error('Rollback failed', {
        error: error.message,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Get migration status
   */
  async getStatus() {
    try {
      // Ensure database connection is established
      if (!this.db.isConnected) {
        await this.db.initialize();
      }

      // Create migrations table if it doesn't exist
      await this.createMigrationsTable();

      const migrationFiles = await this.getMigrationFiles();
      const appliedMigrations = await this.getAppliedMigrations();

      const status = migrationFiles.map(file => {
        const version = this.getVersionFromFilename(file);
        return {
          version,
          filename: file,
          applied: appliedMigrations.includes(version),
          appliedAt: null // Could be enhanced to include timestamp
        };
      });

      // Get applied timestamps
      const appliedDetails = await this.getAppliedMigrationDetails();
      status.forEach(migration => {
        const detail = appliedDetails.find(d => d.version === migration.version);
        if (detail) {
          migration.appliedAt = detail.applied_at;
        }
      });

      return {
        total: migrationFiles.length,
        applied: appliedMigrations.length,
        pending: migrationFiles.length - appliedMigrations.length,
        migrations: status
      };

    } catch (error) {
      logger.error('Failed to get migration status', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Create migrations tracking table
   */
  async createMigrationsTable() {
    const query = `
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version VARCHAR(255) PRIMARY KEY,
        applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `;

    await this.db.query(query);
  }

  /**
   * Get list of migration files
   */
  async getMigrationFiles() {
    try {
      const files = await fs.readdir(this.migrationsPath);
      
      return files
        .filter(file => file.endsWith('.sql') && !file.includes('rollback'))
        .sort(); // Ensure migrations are applied in order

    } catch (error) {
      if (error.code === 'ENOENT') {
        logger.warn('Migrations directory not found', {
          path: this.migrationsPath
        });
        return [];
      }
      throw error;
    }
  }

  /**
   * Get list of applied migrations
   */
  async getAppliedMigrations() {
    try {
      const result = await this.db.query(
        'SELECT version FROM schema_migrations ORDER BY version'
      );
      
      return result.rows.map(row => row.version);

    } catch (error) {
      // If table doesn't exist, return empty array
      if (error.code === '42P01') {
        return [];
      }
      throw error;
    }
  }

  /**
   * Get applied migration details with timestamps
   */
  async getAppliedMigrationDetails() {
    try {
      const result = await this.db.query(
        'SELECT version, applied_at FROM schema_migrations ORDER BY version'
      );
      
      return result.rows;

    } catch (error) {
      if (error.code === '42P01') {
        return [];
      }
      throw error;
    }
  }

  /**
   * Get the last applied migration
   */
  async getLastAppliedMigration() {
    try {
      const result = await this.db.query(
        'SELECT version, applied_at FROM schema_migrations ORDER BY version DESC LIMIT 1'
      );
      
      return result.rows.length > 0 ? result.rows[0] : null;

    } catch (error) {
      if (error.code === '42P01') {
        return null;
      }
      throw error;
    }
  }

  /**
   * Apply a single migration
   */
  async applyMigration(filename) {
    const version = this.getVersionFromFilename(filename);
    const migrationPath = path.join(this.migrationsPath, filename);

    try {
      logger.info(`Applying migration: ${filename}`);

      // Read migration file
      const migrationSQL = await fs.readFile(migrationPath, 'utf8');

      // Execute migration in a transaction
      await this.db.transaction(async (client) => {
        // Execute the migration SQL
        await client.query(migrationSQL);

        // Record the migration as applied
        await client.query(
          'INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT (version) DO NOTHING',
          [version]
        );
      });

      logger.info(`Successfully applied migration: ${filename}`);

    } catch (error) {
      logger.error(`Failed to apply migration: ${filename}`, {
        error: error.message,
        version
      });
      throw error;
    }
  }

  /**
   * Apply a rollback
   */
  async applyRollback(filename, version) {
    const rollbackPath = path.join(this.migrationsPath, filename);

    try {
      logger.info(`Applying rollback: ${filename}`);

      // Read rollback file
      const rollbackSQL = await fs.readFile(rollbackPath, 'utf8');

      // Execute rollback in a transaction
      await this.db.transaction(async (client) => {
        // Execute the rollback SQL
        await client.query(rollbackSQL);

        // Remove the migration record
        await client.query(
          'DELETE FROM schema_migrations WHERE version = $1',
          [version]
        );
      });

      logger.info(`Successfully applied rollback: ${filename}`);

    } catch (error) {
      logger.error(`Failed to apply rollback: ${filename}`, {
        error: error.message,
        version
      });
      throw error;
    }
  }

  /**
   * Extract version from migration filename
   */
  getVersionFromFilename(filename) {
    // Extract version from filename like "001_initial_schema.sql"
    const match = filename.match(/^(\d+)_/);
    return match ? match[1] : filename.replace('.sql', '');
  }

  /**
   * Get rollback filename for a version
   */
  getRollbackFilename(version) {
    return `${version}_rollback.sql`;
  }

  /**
   * Create a new migration file
   */
  async createMigration(name) {
    try {
      // Get next version number
      const migrationFiles = await this.getMigrationFiles();
      const lastVersion = migrationFiles.length > 0 
        ? parseInt(this.getVersionFromFilename(migrationFiles[migrationFiles.length - 1]), 10)
        : 0;
      
      const nextVersion = String(lastVersion + 1).padStart(3, '0');
      const filename = `${nextVersion}_${name.toLowerCase().replace(/\s+/g, '_')}.sql`;
      const filepath = path.join(this.migrationsPath, filename);

      // Create migration template
      const template = `-- Migration: ${filename}
-- Description: ${name}
-- Created: ${new Date().toISOString().split('T')[0]}

-- Add your migration SQL here
-- Example:
-- CREATE TABLE example (
--   id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
--   name VARCHAR(255) NOT NULL,
--   created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
-- );

-- Don't forget to update the schema_migrations table
INSERT INTO schema_migrations (version) VALUES ('${nextVersion}')
ON CONFLICT (version) DO NOTHING;
`;

      await fs.writeFile(filepath, template);

      logger.info(`Created migration file: ${filename}`);
      return { filename, filepath, version: nextVersion };

    } catch (error) {
      logger.error('Failed to create migration', {
        error: error.message,
        name
      });
      throw error;
    }
  }

  /**
   * Validate migration files
   */
  async validate() {
    try {
      const migrationFiles = await this.getMigrationFiles();
      const issues = [];

      for (const file of migrationFiles) {
        const filepath = path.join(this.migrationsPath, file);
        const content = await fs.readFile(filepath, 'utf8');

        // Check for common issues
        if (!content.trim()) {
          issues.push(`${file}: Empty migration file`);
        }

        if (!content.includes('INSERT INTO schema_migrations')) {
          issues.push(`${file}: Missing schema_migrations insert`);
        }

        // Check for potentially dangerous operations
        const dangerousPatterns = [
          /DROP\s+TABLE/i,
          /DROP\s+DATABASE/i,
          /TRUNCATE/i,
          /DELETE\s+FROM.*WHERE/i
        ];

        dangerousPatterns.forEach(pattern => {
          if (pattern.test(content)) {
            issues.push(`${file}: Contains potentially dangerous operation: ${pattern.source}`);
          }
        });
      }

      return {
        valid: issues.length === 0,
        issues,
        totalFiles: migrationFiles.length
      };

    } catch (error) {
      logger.error('Migration validation failed', {
        error: error.message
      });
      throw error;
    }
  }
}

module.exports = new DatabaseMigrator();