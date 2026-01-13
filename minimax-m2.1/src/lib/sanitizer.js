const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

function sanitizeHTML(input, allowedTags = [], allowedAttributes = {}) {
  if (typeof input !== 'string') {
    return '';
  }

  const config = {
    ALLOWED_TAGS: allowedTags.length > 0 ? allowedTags : [],
    ALLOWED_ATTR: allowedAttributes,
    KEEP_CONTENT: true,
    RETURN_DOM: false,
    RETURN_DOM_FRAGMENT: false,
    WHOLE_DOCUMENT: false
  };

  return DOMPurify.sanitize(input, config);
}

function sanitizePlainText(input) {
  if (typeof input !== 'string') {
    return '';
  }

  return input
    .replace(/[<>]/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+=/gi, '')
    .trim();
}

function sanitizeSearchQuery(input) {
  if (typeof input !== 'string') {
    return '';
  }

  return input
    .replace(/[<>\"\'\\]/g, '')
    .replace(/(\b)(select|insert|update|delete|drop|union|exec|execute)/gi, '')
    .trim()
    .substring(0, 100);
}

const XSS_PATTERNS = [
  /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
  /javascript\s*:/gi,
  /on\w+\s*=/gi,
  /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
  /<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi,
  /<embed\b[^<]*(?:(?!<\/embed>)<[^<]*)*<\/embed>/gi,
  /expression\s*\(/gi,
  /data\s*:/gi,
  /vbscript\s*:/gi
];

function detectXSS(input) {
  if (typeof input !== 'string') {
    return false;
  }

  return XSS_PATTERNS.some(pattern => pattern.test(input));
}

function sanitizeForStorage(input) {
  if (typeof input !== 'string') {
    return '';
  }

  return input
    .replace(/\0/g, '')
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .substring(0, 10000);
}

module.exports = {
  sanitizeHTML,
  sanitizePlainText,
  sanitizeSearchQuery,
  detectXSS,
  sanitizeForStorage
};
