import assert from 'node:assert/strict';
import { test } from 'node:test';
import pg from 'pg';
import { runMigrations } from '../scripts/migrate.js';
import { DuplicateUserError, NoteQuotaError } from '../src/errors.js';
import { PostgresNoteRepository, PostgresUserRepository } from '../src/repositories.js';
import { hashPassword } from '../src/security/password.js';

const databaseUrl =
  process.env['TEST_DATABASE_URL'] ??
  (process.env['NODE_ENV'] === 'test' ? process.env['DATABASE_URL'] : undefined);

test(
  'PostgreSQL repositories enforce ownership, concurrency, uniqueness, and quotas',
  { skip: databaseUrl === undefined ? 'set TEST_DATABASE_URL to run PostgreSQL integration tests' : false },
  async () => {
    assert.ok(databaseUrl);
    const databaseName = decodeURIComponent(new URL(databaseUrl).pathname.slice(1));
    assert.match(
      databaseName,
      /_test$/u,
      'refusing to truncate a database whose name does not end in _test',
    );

    const pool = new pg.Pool({
      connectionString: databaseUrl,
      ssl: false,
      max: 4,
      connectionTimeoutMillis: 5_000,
      statement_timeout: 5_000,
    });

    try {
      await runMigrations(pool);
      await runMigrations(pool); // Migration application must be idempotent.
      await pool.query('TRUNCATE notes, users, user_sessions CASCADE');

      const users = new PostgresUserRepository(pool);
      const notes = new PostgresNoteRepository(pool, 10);
      const passwordHash = await hashPassword('a test-only password phrase');
      const alice = await users.create('alice@example.test', passwordHash);
      const bob = await users.create('bob@example.test', passwordHash);

      await assert.rejects(
        users.create('alice@example.test', passwordHash),
        (error: unknown) => error instanceof DuplicateUserError,
      );
      assert.equal((await users.findByEmail('alice@example.test'))?.passwordHash, passwordHash);

      const injectionText = "Robert'); DROP TABLE notes; --";
      const aliceNote = await notes.create(alice.id, {
        title: injectionText,
        content: '<script>stored as plain text</script>',
      });
      const bobNote = await notes.create(bob.id, {
        title: 'Bob private',
        content: 'Only Bob may change this.',
      });

      const aliceList = await notes.list(alice.id);
      assert.deepEqual(aliceList.map((note) => note.id), [aliceNote.id]);
      assert.equal(aliceList[0]?.title, injectionText);
      assert.equal(await notes.find(alice.id, bobNote.id), undefined);
      assert.equal(
        await notes.update(alice.id, bobNote.id, {
          title: 'Stolen',
          content: 'Must not change.',
          version: bobNote.version,
        }),
        'not_found',
      );
      assert.equal(await notes.delete(alice.id, bobNote.id), false);
      assert.deepEqual(await notes.find(bob.id, bobNote.id), bobNote);

      assert.equal(
        await notes.update(alice.id, aliceNote.id, {
          title: 'Updated safely',
          content: 'Current version wins.',
          version: aliceNote.version,
        }),
        'updated',
      );
      assert.equal(
        await notes.update(alice.id, aliceNote.id, {
          title: 'Stale overwrite',
          content: 'Must be rejected.',
          version: aliceNote.version,
        }),
        'conflict',
      );

      const quotaUser = await users.create('quota@example.test', passwordHash);
      const quotaNotes = new PostgresNoteRepository(pool, 1);
      const concurrentCreates = await Promise.allSettled([
        quotaNotes.create(quotaUser.id, { title: 'First', content: 'One' }),
        quotaNotes.create(quotaUser.id, { title: 'Second', content: 'Two' }),
      ]);
      assert.equal(
        concurrentCreates.filter((result) => result.status === 'fulfilled').length,
        1,
      );
      const rejection = concurrentCreates.find((result) => result.status === 'rejected');
      assert.ok(rejection?.status === 'rejected' && rejection.reason instanceof NoteQuotaError);
      assert.equal((await quotaNotes.list(quotaUser.id)).length, 1);
    } finally {
      await pool.end();
    }
  },
);
