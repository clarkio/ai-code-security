import argon2 from 'argon2';
import { HttpError } from '../errors.js';

const ARGON2_OPTIONS = Object.freeze({
  type: argon2.argon2id,
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
  hashLength: 32,
});

// This is an Argon2id hash of a non-secret random value. It makes unknown-user
// logins perform the same expensive verification step as known-user logins.
const DUMMY_PASSWORD_HASH =
  '$argon2id$v=19$m=19456,t=2,p=1$fdZvo77r2GoIQ+eae4k4BQ$x76dzWdURBV71beTbK6rFwNDR1Z5zMlMLjiPNOLO8W4';
const ARGON2_PARAMETERS = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$/u;

const MAX_CONCURRENT_PASSWORD_JOBS = 4;
let activePasswordJobs = 0;

async function withPasswordCapacity<T>(work: () => Promise<T>): Promise<T> {
  if (activePasswordJobs >= MAX_CONCURRENT_PASSWORD_JOBS) {
    throw new HttpError(
      503,
      'Authentication is temporarily busy. Please try again shortly.',
      'PASSWORD_WORK_CAPACITY',
    );
  }

  activePasswordJobs += 1;
  try {
    return await work();
  } finally {
    activePasswordJobs -= 1;
  }
}

function storedHashHasSafeCost(passwordHash: string | undefined): passwordHash is string {
  if (passwordHash === undefined || passwordHash.length > 512) return false;
  const parameters = ARGON2_PARAMETERS.exec(passwordHash);
  if (parameters === null) return false;
  const memory = Number(parameters[1]);
  const time = Number(parameters[2]);
  const parallelism = Number(parameters[3]);
  return (
    Number.isSafeInteger(memory) &&
    memory >= 19_456 &&
    memory <= 65_536 &&
    Number.isSafeInteger(time) &&
    time >= 2 &&
    time <= 4 &&
    Number.isSafeInteger(parallelism) &&
    parallelism >= 1 &&
    parallelism <= 2
  );
}

export async function hashPassword(password: string): Promise<string> {
  return withPasswordCapacity(() => argon2.hash(password, ARGON2_OPTIONS));
}

export async function verifyPassword(passwordHash: string | undefined, password: string): Promise<boolean> {
  return withPasswordCapacity(async () => {
    try {
      const hashIsSafe = storedHashHasSafeCost(passwordHash);
      const valid = await argon2.verify(hashIsSafe ? passwordHash : DUMMY_PASSWORD_HASH, password);
      return hashIsSafe && valid;
    } catch {
      // Corrupt hashes fail closed and are intentionally indistinguishable from
      // an incorrect password to the caller.
      return false;
    }
  });
}
