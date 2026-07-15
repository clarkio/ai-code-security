import assert from 'node:assert/strict';
import { test } from 'node:test';
import { HttpError } from '../src/errors.js';
import { hashPassword, verifyPassword } from '../src/security/password.js';

test('password hashing has a process-wide concurrency ceiling and recovers capacity', async () => {
  const jobs = Array.from({ length: 5 }, (_value, index) =>
    hashPassword(`concurrency test password number ${index}`),
  );
  const results = await Promise.allSettled(jobs);
  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 4);
  const rejected = results.find((result) => result.status === 'rejected');
  assert.ok(
    rejected?.status === 'rejected' &&
      rejected.reason instanceof HttpError &&
      rejected.reason.status === 503,
  );

  const hash = await hashPassword('capacity is available after completed jobs');
  assert.equal(await verifyPassword(hash, 'capacity is available after completed jobs'), true);
  const attackerControlledCost = hash.replace('m=19456', 'm=999999999');
  assert.equal(
    await verifyPassword(attackerControlledCost, 'capacity is available after completed jobs'),
    false,
  );
});
