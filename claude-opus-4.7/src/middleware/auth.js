'use strict';

const { findUserById } = require('../db');

// Loads the user from the session on every request and attaches a sanitized
// view object. Session storage holds only the user id; we re-fetch on each
// request so a deleted user cannot keep using a live session.
function attachUser(req, res, next) {
  const uid = req.session && req.session.userId;
  if (uid) {
    const user = findUserById(uid);
    if (user) {
      req.user = user;
      res.locals.currentUser = { id: user.id, username: user.username };
    } else {
      // Session refers to a user that no longer exists — drop it.
      req.session.destroy(() => next());
      return;
    }
  } else {
    res.locals.currentUser = null;
  }
  next();
}

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.redirect('/login');
  }
  next();
}

function requireGuest(req, res, next) {
  if (req.user) {
    return res.redirect('/notes');
  }
  next();
}

module.exports = { attachUser, requireAuth, requireGuest };
