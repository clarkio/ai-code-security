import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import type pg from 'pg';
import { parseConfig } from '../src/config.js';
import { createPool } from '../src/db.js';

const MIGRATION_FILE = /^\d{3}_[a-z0-9_]+\.sql$/u;
const MIGRATION_LOCK_ID = 1_937_462_911;

interface AppliedMigration {
  name: string;
  checksum: string;
}

export async function runMigrations(pool: pg.Pool): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK_ID]);
    await client.query(`
      CREATE TABLE IF NOT EXISTS app_migrations (
        name varchar(255) PRIMARY KEY,
        checksum char(64) NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);

    const migrationsDirectory = path.join(process.cwd(), 'migrations');
    const names = (await readdir(migrationsDirectory)).filter((name) => MIGRATION_FILE.test(name)).sort();
    if (names.length === 0) throw new Error('No database migrations were found');
    const appliedResult = await client.query<AppliedMigration>('SELECT name, checksum FROM app_migrations');
    const applied = new Map(appliedResult.rows.map((row) => [row.name, row.checksum]));
    for (const appliedName of applied.keys()) {
      if (!names.includes(appliedName)) {
        throw new Error(`Database migration ${appliedName} is not present in this release`);
      }
    }

    for (const name of names) {
      const sql = await readFile(path.join(migrationsDirectory, name), 'utf8');
      const checksum = createHash('sha256').update(sql, 'utf8').digest('hex');
      const existingChecksum = applied.get(name);
      if (existingChecksum !== undefined) {
        if (existingChecksum !== checksum) {
          throw new Error(`Applied migration ${name} has been modified`);
        }
        continue;
      }

      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO app_migrations (name, checksum) VALUES ($1, $2)', [name, checksum]);
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      }
    }
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK_ID]).catch(() => undefined);
    client.release();
  }
}

async function main(): Promise<void> {
  const pool = createPool(parseConfig());
  try {
    await runMigrations(pool);
    process.stdout.write('Database migrations are current.\n');
  } finally {
    await pool.end();
  }
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(path.resolve(invokedPath)).href) {
  main().catch((error: unknown) => {
    const kind = error instanceof Error ? error.name : 'UnknownError';
    process.stderr.write(`Migration failed (${kind}).\n`);
    process.exitCode = 1;
  });
}
