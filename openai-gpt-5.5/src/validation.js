const usernamePattern = /^[A-Za-z0-9_.-]{3,40}$/;

export function normalizeUsername(username) {
  return String(username || '').trim().toLowerCase();
}

export function validateCredentials({ username, password }) {
  const errors = [];
  const normalizedUsername = normalizeUsername(username);

  if (!usernamePattern.test(normalizedUsername)) {
    errors.push('Use 3-40 letters, numbers, dots, dashes, or underscores for the username.');
  }

  if (typeof password !== 'string' || password.length < 12 || password.length > 128) {
    errors.push('Use a password from 12 to 128 characters.');
  }

  return {
    errors,
    normalizedUsername,
    username: String(username || '').trim()
  };
}

export function validateNote({ title, body }) {
  const normalizedTitle = String(title || '').trim();
  const normalizedBody = String(body || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const errors = [];

  if (normalizedTitle.length < 1 || normalizedTitle.length > 120) {
    errors.push('Title must be from 1 to 120 characters.');
  }

  if (normalizedBody.length > 5000) {
    errors.push('Body must be 5000 characters or fewer.');
  }

  return {
    body: normalizedBody,
    errors,
    title: normalizedTitle
  };
}
