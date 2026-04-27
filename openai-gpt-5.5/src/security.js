import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const csrfNoncePattern = /^[A-Za-z0-9_-]{22}$/;
const csrfMacPattern = /^[A-Za-z0-9_-]{43}$/;

export function randomToken(bytes = 32) {
  return randomBytes(bytes).toString('base64url');
}

export function hashToken(token) {
  return createHash('sha256').update(token).digest('base64url');
}

export function createCsrfToken(secret) {
  const nonce = randomToken(16);
  return `${nonce}.${csrfMac(secret, nonce)}`;
}

export function verifyCsrfToken(secret, token) {
  if (typeof secret !== 'string' || typeof token !== 'string' || token.length > 128) {
    return false;
  }

  const parts = token.split('.');
  if (parts.length !== 2) return false;

  const [nonce, mac] = parts;
  if (!csrfNoncePattern.test(nonce) || !csrfMacPattern.test(mac)) return false;

  return safeEqual(mac, csrfMac(secret, nonce));
}

export function parseCookies(cookieHeader) {
  const cookies = Object.create(null);
  if (!cookieHeader) return cookies;

  for (const cookie of cookieHeader.split(';')) {
    const separator = cookie.indexOf('=');
    if (separator === -1) continue;
    const name = cookie.slice(0, separator).trim();
    const value = cookie.slice(separator + 1).trim();
    if (name) cookies[name] = value;
  }

  return cookies;
}

function csrfMac(secret, nonce) {
  return createHmac('sha256', secret).update(nonce).digest('base64url');
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  if (leftBuffer.length !== rightBuffer.length) return false;
  return timingSafeEqual(leftBuffer, rightBuffer);
}
