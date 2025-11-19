const { get } = require('../db');

const attachUser = async (req, _res, next) => {
  try {
    if (!req.session || !req.session.userId) {
      req.user = null;
      return next();
    }
    const user = await get('SELECT id, username, created_at FROM users WHERE id = ?', [
      req.session.userId,
    ]);
    req.user = user || null;
    if (!user && req.session) {
      req.session.destroy(() => {});
    }
    return next();
  } catch (err) {
    return next(err);
  }
};

const requireAuth = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  return next();
};

module.exports = { attachUser, requireAuth };
