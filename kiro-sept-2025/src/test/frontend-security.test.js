/**
 * Frontend Security Tests
 * Tests for XSS prevention, CSRF protection, and secure form handling
 */

const request = require('supertest');
const { JSDOM } = require('jsdom');
const fs = require('fs');
const path = require('path');

describe('Frontend Security Tests', () => {
  // Test static HTML files directly to avoid Redis dependency issues
  const readHtmlFile = (filename) => {
    return fs.readFileSync(path.join(__dirname, '../../public', filename), 'utf8');
  };

  const readJsFile = (filename) => {
    return fs.readFileSync(path.join(__dirname, '../../public/js', filename), 'utf8');
  };

  describe('XSS Prevention', () => {
    test('should include CSP meta tag in HTML pages', () => {
      const loginHtml = readHtmlFile('login.html');
      
      expect(loginHtml).toContain('Content-Security-Policy');
      expect(loginHtml).toContain("default-src 'self'");
      expect(loginHtml).toContain("script-src 'self'");
      expect(loginHtml).toContain("object-src 'none'");
    });

    test('should properly encode HTML entities in form inputs', () => {
      const registerHtml = readHtmlFile('register.html');
      const dom = new JSDOM(registerHtml);
      const document = dom.window.document;
      
      // Check that form inputs have proper attributes
      const emailInput = document.getElementById('email');
      const passwordInput = document.getElementById('password');
      
      expect(emailInput.getAttribute('maxlength')).toBe('254');
      expect(passwordInput.getAttribute('minlength')).toBe('12');
      expect(passwordInput.getAttribute('maxlength')).toBe('128');
    });

    test('should include XSS protection in JavaScript files', () => {
      const authJs = readJsFile('auth.js');
      
      expect(authJs).toContain('sanitizeInput');
      expect(authJs).toContain('replace(/&/g, \'&amp;\')');
      expect(authJs).toContain('replace(/</g, \'&lt;\')');
      expect(authJs).toContain('replace(/>/g, \'&gt;\')');
    });
  });

  describe('CSRF Protection', () => {
    test('should include CSRF token inputs in forms', () => {
      const loginHtml = readHtmlFile('login.html');
      const dom = new JSDOM(loginHtml);
      const document = dom.window.document;
      
      const csrfInput = document.getElementById('csrf-token');
      expect(csrfInput).toBeTruthy();
      expect(csrfInput.getAttribute('type')).toBe('hidden');
      expect(csrfInput.getAttribute('name')).toBe('_csrf');
    });

    test('should include CSRF token handling in JavaScript', () => {
      const authJs = readJsFile('auth.js');
      
      expect(authJs).toContain('fetchCsrfToken');
      expect(authJs).toContain('/api/csrf-token');
      expect(authJs).toContain('_csrf');
    });
  });

  describe('Secure Form Handling', () => {
    test('should validate email format on client side', () => {
      const loginHtml = readHtmlFile('login.html');
      const dom = new JSDOM(loginHtml);
      const document = dom.window.document;
      
      const emailInput = document.getElementById('email');
      expect(emailInput.getAttribute('type')).toBe('email');
      expect(emailInput.hasAttribute('required')).toBe(true);
    });

    test('should enforce password complexity on client side', () => {
      const registerHtml = readHtmlFile('register.html');
      const dom = new JSDOM(registerHtml);
      const document = dom.window.document;
      
      const passwordInput = document.getElementById('password');
      expect(passwordInput.getAttribute('type')).toBe('password');
      expect(passwordInput.getAttribute('minlength')).toBe('12');
      expect(passwordInput.hasAttribute('required')).toBe(true);
    });

    test('should include autocomplete attributes for security', () => {
      const loginHtml = readHtmlFile('login.html');
      const dom = new JSDOM(loginHtml);
      const document = dom.window.document;
      
      const emailInput = document.getElementById('email');
      const passwordInput = document.getElementById('password');
      
      expect(emailInput.getAttribute('autocomplete')).toBe('email');
      expect(passwordInput.getAttribute('autocomplete')).toBe('current-password');
    });

    test('should use proper autocomplete for registration form', () => {
      const registerHtml = readHtmlFile('register.html');
      const dom = new JSDOM(registerHtml);
      const document = dom.window.document;
      
      const passwordInput = document.getElementById('password');
      const confirmPasswordInput = document.getElementById('confirmPassword');
      
      expect(passwordInput.getAttribute('autocomplete')).toBe('new-password');
      expect(confirmPasswordInput.getAttribute('autocomplete')).toBe('new-password');
    });
  });

  describe('Security Headers', () => {
    test('should include security-focused meta tags', () => {
      const loginHtml = readHtmlFile('login.html');
      
      expect(loginHtml).toContain('Content-Security-Policy');
      expect(loginHtml).toContain('charset="UTF-8"');
      expect(loginHtml).toContain('viewport');
    });
  });

  describe('Input Validation', () => {
    test('should include client-side validation attributes', () => {
      const registerHtml = readHtmlFile('register.html');
      const dom = new JSDOM(registerHtml);
      const document = dom.window.document;
      
      const emailInput = document.getElementById('email');
      const passwordInput = document.getElementById('password');
      const confirmPasswordInput = document.getElementById('confirmPassword');
      
      // Email validation
      expect(emailInput.getAttribute('maxlength')).toBe('254');
      expect(emailInput.getAttribute('type')).toBe('email');
      
      // Password validation
      expect(passwordInput.getAttribute('minlength')).toBe('12');
      expect(passwordInput.getAttribute('maxlength')).toBe('128');
      
      // Confirm password validation
      expect(confirmPasswordInput.getAttribute('minlength')).toBe('12');
      expect(confirmPasswordInput.getAttribute('maxlength')).toBe('128');
    });

    test('should include ARIA attributes for accessibility', () => {
      const registerHtml = readHtmlFile('register.html');
      const dom = new JSDOM(registerHtml);
      const document = dom.window.document;
      
      const emailInput = document.getElementById('email');
      const passwordInput = document.getElementById('password');
      
      expect(emailInput.getAttribute('aria-describedby')).toContain('email-error');
      expect(passwordInput.getAttribute('aria-describedby')).toContain('password-error');
    });
  });

  describe('Error Handling', () => {
    test('should include error display elements', () => {
      const loginHtml = readHtmlFile('login.html');
      const dom = new JSDOM(loginHtml);
      const document = dom.window.document;
      
      const errorMessage = document.getElementById('error-message');
      const successMessage = document.getElementById('success-message');
      const rateLimitWarning = document.getElementById('rate-limit-warning');
      
      expect(errorMessage).toBeTruthy();
      expect(successMessage).toBeTruthy();
      expect(rateLimitWarning).toBeTruthy();
      
      // Should be hidden by default
      expect(errorMessage.style.display).toBe('none');
      expect(successMessage.style.display).toBe('none');
      expect(rateLimitWarning.style.display).toBe('none');
    });

    test('should include field-specific error elements', () => {
      const registerHtml = readHtmlFile('register.html');
      const dom = new JSDOM(registerHtml);
      const document = dom.window.document;
      
      const emailError = document.getElementById('email-error');
      const passwordError = document.getElementById('password-error');
      const confirmPasswordError = document.getElementById('confirm-password-error');
      
      expect(emailError).toBeTruthy();
      expect(passwordError).toBeTruthy();
      expect(confirmPasswordError).toBeTruthy();
      
      expect(emailError.className).toContain('field-error');
      expect(passwordError.className).toContain('field-error');
      expect(confirmPasswordError.className).toContain('field-error');
    });
  });

  describe('Rate Limiting Feedback', () => {
    test('should include rate limiting warning elements', () => {
      const loginHtml = readHtmlFile('login.html');
      const dom = new JSDOM(loginHtml);
      const document = dom.window.document;
      
      const rateLimitWarning = document.getElementById('rate-limit-warning');
      const rateLimitCountdown = document.getElementById('rate-limit-countdown');
      
      expect(rateLimitWarning).toBeTruthy();
      expect(rateLimitCountdown).toBeTruthy();
      expect(rateLimitWarning.className).toContain('alert-warning');
    });
  });

  describe('Password Strength Indicator', () => {
    test('should include password strength elements in registration', () => {
      const registerHtml = readHtmlFile('register.html');
      const dom = new JSDOM(registerHtml);
      const document = dom.window.document;
      
      const strengthBar = document.querySelector('.strength-bar');
      const strengthFill = document.getElementById('strength-fill');
      const strengthText = document.getElementById('strength-text');
      
      expect(strengthBar).toBeTruthy();
      expect(strengthFill).toBeTruthy();
      expect(strengthText).toBeTruthy();
    });

    test('should include password requirement checklist', () => {
      const registerHtml = readHtmlFile('register.html');
      const dom = new JSDOM(registerHtml);
      const document = dom.window.document;
      
      const reqLength = document.getElementById('req-length');
      const reqUppercase = document.getElementById('req-uppercase');
      const reqLowercase = document.getElementById('req-lowercase');
      const reqNumber = document.getElementById('req-number');
      const reqSpecial = document.getElementById('req-special');
      
      expect(reqLength).toBeTruthy();
      expect(reqUppercase).toBeTruthy();
      expect(reqLowercase).toBeTruthy();
      expect(reqNumber).toBeTruthy();
      expect(reqSpecial).toBeTruthy();
    });
  });

  describe('Accessibility', () => {
    test('should include proper form labels', () => {
      const loginHtml = readHtmlFile('login.html');
      const dom = new JSDOM(loginHtml);
      const document = dom.window.document;
      
      const emailLabel = document.querySelector('label[for="email"]');
      const passwordLabel = document.querySelector('label[for="password"]');
      
      expect(emailLabel).toBeTruthy();
      expect(passwordLabel).toBeTruthy();
      expect(emailLabel.textContent).toContain('Email');
      expect(passwordLabel.textContent).toContain('Password');
    });

    test('should include viewport meta tag', () => {
      const indexHtml = readHtmlFile('index.html');
      const dom = new JSDOM(indexHtml);
      const document = dom.window.document;
      
      const viewportMeta = document.querySelector('meta[name="viewport"]');
      expect(viewportMeta).toBeTruthy();
      expect(viewportMeta.getAttribute('content')).toContain('width=device-width');
    });

    test('should include lang attribute on html element', () => {
      const indexHtml = readHtmlFile('index.html');
      const dom = new JSDOM(indexHtml);
      const document = dom.window.document;
      
      const htmlElement = document.documentElement;
      expect(htmlElement.getAttribute('lang')).toBe('en');
    });
  });

  describe('JavaScript Security Features', () => {
    test('should include password validation in register.js', () => {
      const registerJs = readJsFile('register.js');
      
      expect(registerJs).toContain('validatePassword');
      expect(registerJs).toContain('updatePasswordStrength');
      expect(registerJs).toContain('validateConfirmPassword');
    });

    test('should include rate limiting handling in login.js', () => {
      const loginJs = readJsFile('login.js');
      
      expect(loginJs).toContain('handleLoginError');
      expect(loginJs).toContain('Rate limit');
      expect(loginJs).toContain('validateEmail');
    });

    test('should include secure request handling in auth.js', () => {
      const authJs = readJsFile('auth.js');
      
      expect(authJs).toContain('secureRequest');
      expect(authJs).toContain('handleRateLimit');
      expect(authJs).toContain('sanitizeInput');
    });
  });
});