const { verifyAccessToken, isTokenValid } = require('../lib/auth');
const { sanitizePlainText } = require('../lib/sanitizer');

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const token = authHeader.substring(7);
  const decoded = verifyAccessToken(token);

  if (!decoded) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  req.user = {
    id: decoded.userId
  };

  next();
}

async function authenticateSocket(token) {
  if (!token) {
    return null;
  }

  const decoded = verifyAccessToken(token);
  if (!decoded) {
    return null;
  }

  const isValid = await isTokenValid(token);
  if (!isValid) {
    return null;
  }

  return decoded.userId;
}

function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next();
  }

  const token = authHeader.substring(7);
  const decoded = verifyAccessToken(token);

  if (decoded) {
    req.user = { id: decoded.userId };
  }

  next();
}

function requireAuth(req, res, next) {
  if (!req.user || !req.user.id) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
}

module.exports = {
  authenticate,
  authenticateSocket,
  optionalAuth,
  requireAuth
};
