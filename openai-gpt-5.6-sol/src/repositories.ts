import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { DuplicateUserError, NoteQuotaError } from './errors.js';
import type { CreateNoteInput, UpdateNoteInput } from './validation.js';

export interface UserRecord {
  readonly id: string;
  readonly email: string;
  readonly passwordHash: string;
}

export interface NoteRecord {
  readonly id: string;
  readonly title: string;
  readonly content: string;
  readonly version: number;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export interface UserRepository {
  findByEmail(email: string): Promise<UserRecord | undefined>;
  create(email: string, passwordHash: string): Promise<UserRecord>;
}

export type UpdateResult = 'updated' | 'not_found' | 'conflict';

export interface NoteRepository {
  list(userId: string): Promise<readonly NoteRecord[]>;
  find(userId: string, noteId: string): Promise<NoteRecord | undefined>;
  create(userId: string, input: CreateNoteInput): Promise<NoteRecord>;
  update(userId: string, noteId: string, input: UpdateNoteInput): Promise<UpdateResult>;
  delete(userId: string, noteId: string): Promise<boolean>;
}

interface UserRow {
  id: string;
  email: string;
  password_hash: string;
}

interface NoteRow {
  id: string;
  title: string;
  content: string;
  version: number;
  created_at: Date;
  updated_at: Date;
}

function userFromRow(row: UserRow): UserRecord {
  return { id: row.id, email: row.email, passwordHash: row.password_hash };
}

function noteFromRow(row: NoteRow): NoteRecord {
  return {
    id: row.id,
    title: row.title,
    content: row.content,
    version: row.version,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function isPgErrorWithCode(error: unknown, code: string): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === code
  );
}

export class PostgresUserRepository implements UserRepository {
  public constructor(private readonly pool: pg.Pool) {}

  public async findByEmail(email: string): Promise<UserRecord | undefined> {
    const result = await this.pool.query<UserRow>(
      `SELECT id, email, password_hash
         FROM users
        WHERE email = $1
        LIMIT 1`,
      [email],
    );
    const row = result.rows[0];
    return row === undefined ? undefined : userFromRow(row);
  }

  public async create(email: string, passwordHash: string): Promise<UserRecord> {
    try {
      const result = await this.pool.query<UserRow>(
        `INSERT INTO users (id, email, password_hash)
         VALUES ($1, $2, $3)
         RETURNING id, email, password_hash`,
        [randomUUID(), email, passwordHash],
      );
      const row = result.rows[0];
      if (row === undefined) throw new Error('User insert returned no row');
      return userFromRow(row);
    } catch (error) {
      if (isPgErrorWithCode(error, '23505')) throw new DuplicateUserError();
      throw error;
    }
  }
}

export class PostgresNoteRepository implements NoteRepository {
  public constructor(
    private readonly pool: pg.Pool,
    private readonly maxNotesPerUser: number,
  ) {}

  public async list(userId: string): Promise<readonly NoteRecord[]> {
    const result = await this.pool.query<NoteRow>(
      `SELECT id, title, content, version, created_at, updated_at
         FROM notes
        WHERE user_id = $1
        ORDER BY updated_at DESC, id DESC
        LIMIT $2`,
      [userId, this.maxNotesPerUser],
    );
    return result.rows.map(noteFromRow);
  }

  public async find(userId: string, noteId: string): Promise<NoteRecord | undefined> {
    const result = await this.pool.query<NoteRow>(
      `SELECT id, title, content, version, created_at, updated_at
         FROM notes
        WHERE id = $1 AND user_id = $2
        LIMIT 1`,
      [noteId, userId],
    );
    const row = result.rows[0];
    return row === undefined ? undefined : noteFromRow(row);
  }

  public async create(userId: string, input: CreateNoteInput): Promise<NoteRecord> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      // Serialize creates for one user so concurrent requests cannot race past
      // the per-account storage quota.
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [userId]);
      const countResult = await client.query<{ count: number }>(
        'SELECT count(*)::integer AS count FROM notes WHERE user_id = $1',
        [userId],
      );
      if ((countResult.rows[0]?.count ?? this.maxNotesPerUser) >= this.maxNotesPerUser) {
        throw new NoteQuotaError();
      }

      const result = await client.query<NoteRow>(
        `INSERT INTO notes (id, user_id, title, content)
         VALUES ($1, $2, $3, $4)
         RETURNING id, title, content, version, created_at, updated_at`,
        [randomUUID(), userId, input.title, input.content],
      );
      const row = result.rows[0];
      if (row === undefined) throw new Error('Note insert returned no row');
      await client.query('COMMIT');
      return noteFromRow(row);
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  public async update(userId: string, noteId: string, input: UpdateNoteInput): Promise<UpdateResult> {
    const result = await this.pool.query<{ id: string }>(
      `UPDATE notes
          SET title = $3,
              content = $4,
              version = version + 1,
              updated_at = now()
        WHERE id = $1 AND user_id = $2 AND version = $5
        RETURNING id`,
      [noteId, userId, input.title, input.content, input.version],
    );
    if (result.rowCount === 1) return 'updated';

    const exists = await this.pool.query<{ exists: boolean }>(
      'SELECT EXISTS(SELECT 1 FROM notes WHERE id = $1 AND user_id = $2) AS exists',
      [noteId, userId],
    );
    return exists.rows[0]?.exists === true ? 'conflict' : 'not_found';
  }

  public async delete(userId: string, noteId: string): Promise<boolean> {
    const result = await this.pool.query(
      'DELETE FROM notes WHERE id = $1 AND user_id = $2',
      [noteId, userId],
    );
    return result.rowCount === 1;
  }
}
