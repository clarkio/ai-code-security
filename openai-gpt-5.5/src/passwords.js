import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);
const keyLength = 64;
const params = Object.freeze({
  N: 16384,
  r: 8,
  p: 1,
  maxmem: 64 * 1024 * 1024
});

export async function hashPassword(password) {
  const salt = cryptoRandomBase64Url(16);
  const derivedKey = await scryptAsync(password, salt, keyLength, params);
  return `scrypt$v=1$n=${params.N}$r=${params.r}$p=${params.p}$${salt}$${derivedKey.toString('base64url')}`;
}

export async function verifyPassword(password, storedHash) {
  const parsed = parseStoredHash(storedHash);
  const salt = parsed?.salt || 'invalid-password-hash-salt';
  const expected = parsed?.hash || Buffer.alloc(keyLength);
  const options = parsed?.params || params;
  const derivedKey = await scryptAsync(password || '', salt, keyLength, options);

  if (derivedKey.length !== expected.length) return false;
  return Boolean(parsed) && timingSafeEqual(derivedKey, expected);
}

function parseStoredHash(storedHash) {
  if (typeof storedHash !== 'string') return null;
  const parts = storedHash.split('$');
  if (parts.length !== 7 || parts[0] !== 'scrypt' || parts[1] !== 'v=1') return null;

  const parsedParams = {
    N: Number(parts[2].slice(2)),
    r: Number(parts[3].slice(2)),
    p: Number(parts[4].slice(2)),
    maxmem: params.maxmem
  };

  if (
    !Number.isInteger(parsedParams.N) ||
    !Number.isInteger(parsedParams.r) ||
    !Number.isInteger(parsedParams.p) ||
    parsedParams.N < 16384 ||
    parsedParams.r < 8 ||
    parsedParams.p < 1
  ) {
    return null;
  }

  const hash = Buffer.from(parts[6], 'base64url');
  if (hash.length !== keyLength) return null;

  return {
    hash,
    params: parsedParams,
    salt: parts[5]
  };
}

function cryptoRandomBase64Url(bytes) {
  return randomBytes(bytes).toString('base64url');
}
