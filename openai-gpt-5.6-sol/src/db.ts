import pg from 'pg';
import type { AppConfig, DatabaseSslMode } from './config.js';

const { Pool } = pg;

function sslOptions(mode: DatabaseSslMode): false | { rejectUnauthorized: boolean } {
  switch (mode) {
    case 'disable':
      return false;
    case 'require':
      return { rejectUnauthorized: false };
    case 'verify-full':
      return { rejectUnauthorized: true };
  }
}

export function createPool(config: AppConfig): pg.Pool {
  return new Pool({
    connectionString: config.databaseUrl,
    ssl: sslOptions(config.databaseSsl),
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    statement_timeout: 5_000,
    query_timeout: 6_000,
    lock_timeout: 3_000,
    idle_in_transaction_session_timeout: 10_000,
    application_name: 'secure-notes',
  });
}

export async function databaseIsReady(pool: pg.Pool): Promise<boolean> {
  // LIMIT 0 checks that the expected columns exist and that the runtime role
  // can read each table without fetching user or session data.
  await pool.query('SELECT id, email, password_hash FROM users LIMIT 0');
  await pool.query('SELECT id, user_id, title, content, version FROM notes LIMIT 0');
  await pool.query('SELECT sid, sess, expire FROM user_sessions LIMIT 0');
  const result = await pool.query<{ migrated: boolean }>(`
    SELECT EXISTS (
      SELECT 1 FROM app_migrations WHERE name = '001_initial_schema.sql'
    ) AS migrated
  `);
  return result.rows[0]?.migrated === true;
}
