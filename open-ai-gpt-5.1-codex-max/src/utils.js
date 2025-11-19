const crypto = require('crypto');

const escapeHtml = (unsafe) =>
  unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');

const safeString = (value) => escapeHtml(String(value ?? ''));

const nonce = () => crypto.randomBytes(16).toString('base64');

module.exports = {
  safeString,
  nonce,
};
