"use strict";

/**
 * CSRF protection.
 *
 * For state-changing requests (POST/PUT/PATCH/DELETE) we require a CSRF token
 * that matches the one stored in the session. The token is provided to the
 * frontend via a meta tag and submitted as the X-CSRF-Token header.
 *
 * GET/HEAD/OPTIONS are exempt (they must be idempotent & side-effect free).
 *
 * NOTE: The token is stored in a signed cookie (not the session) so it survives
 * session regeneration on login/logout. This is the standard pattern used by
 * csurf and similar libraries.
 */

const crypto = require("crypto");
const cookieParser = require("cookie-parser");

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const COOKIE_NAME = "csrf";

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

function csrfMiddleware(req, res, next) {
  // Read token from signed cookie (survives session regeneration)
  let token = req.signedCookies[COOKIE_NAME];
  if (!token) {
    token = generateToken();
    // Signed, HttpOnly cookie — not accessible to JS but sent with requests.
    // SameSite=strict for additional CSRF defense.
    res.cookie(COOKIE_NAME, token, {
      httpOnly: true,
      sameSite: "strict",
      secure: req.secure,
      signed: true,
      path: "/",
    });
  }

  // Expose token to templates (server-rendered) and to JS via meta tag
  res.locals.csrfToken = token;

  if (SAFE_METHODS.has(req.method)) {
    return next();
  }

  const sentToken = req.headers["x-csrf-token"] || req.body._csrf;
  if (!sentToken || sentToken !== token) {
    return res.status(403).json({ error: "CSRF token validation failed" });
  }

  next();
}

module.exports = { csrfMiddleware, generateToken };
