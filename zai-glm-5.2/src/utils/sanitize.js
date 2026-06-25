"use strict";

/**
 * Input sanitization utilities.
 *
 * Notes are stored as plain text (no HTML). We strip any HTML to prevent
 * stored XSS even if the template layer were ever bypassed.
 * Defense in depth: EJS auto-escapes by default, AND we sanitize on write.
 */

// Strip all HTML tags and decode entities — notes are plain text only.
function sanitizePlainText(input) {
  if (typeof input !== "string") return "";
  // Decode common HTML entities first (in case of double-encoding attacks)
  const decoded = input
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/g, "'")
    .replace(/&amp;/g, "&");
  // Remove anything that looks like a tag
  const stripped = decoded.replace(/<[^>]*>/g, "");
  // Collapse excessive whitespace
  return stripped.replace(/\s+/g, " ").trim();
}

// Enforce a max length to prevent memory-exhaustion / DoS
function clampLength(str, max) {
  if (typeof str !== "string") return "";
  return str.length > max ? str.slice(0, max) : str;
}

module.exports = { sanitizePlainText, clampLength };
