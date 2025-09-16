/**
 * Notes Interface Security Tests
 * Tests for secure content rendering, input validation, and XSS prevention in notes management
 */

const { JSDOM } = require('jsdom');
const fs = require('fs');
const path = require('path');

describe('Notes Interface Security Tests', () => {
  // Test static HTML files directly to avoid Redis dependency issues
  const readHtmlFile = (filename) => {
    return fs.readFileSync(path.join(__dirname, '../../public', filename), 'utf8');
  };

  const readJsFile = (filename) => {
    return fs.readFileSync(path.join(__dirname, '../../public/js', filename), 'utf8');
  };

  describe('Dashboard Security', () => {
    test('should include proper CSP headers in dashboard', () => {
      const dashboardHtml = readHtmlFile('dashboard.html');
      
      expect(dashboardHtml).toContain('Content-Security-Policy');
      expect(dashboardHtml).toContain("default-src 'self'");
      expect(dashboardHtml).toContain("script-src 'self'");
      expect(dashboardHtml).toContain("object-src 'none'");
    });

    test('should include authentication check in dashboard.js', () => {
      const dashboardJs = readJsFile('dashboard.js');
      
      expect(dashboardJs).toContain('checkAuthentication');
      expect(dashboardJs).toContain('isAuthenticated');
      expect(dashboardJs).toContain('window.location.href = \'/login\'');
    });

    test('should sanitize content in dashboard display', () => {
      const dashboardJs = readJsFile('dashboard.js');
      
      expect(dashboardJs).toContain('sanitizeInput');
      expect(dashboardJs).toContain('authUtils.sanitizeInput');
      expect(dashboardJs).toContain('createNotePreviewHtml');
    });

    test('should include secure logout functionality', () => {
      const dashboardJs = readJsFile('dashboard.js');
      
      expect(dashboardJs).toContain('handleLogout');
      expect(dashboardJs).toContain('/api/auth/logout');
      expect(dashboardJs).toContain('secureRequest');
    });
  });

  describe('Notes List Security', () => {
    test('should include proper CSP headers in notes page', () => {
      const notesHtml = readHtmlFile('notes.html');
      
      expect(notesHtml).toContain('Content-Security-Policy');
      expect(notesHtml).toContain("default-src 'self'");
      expect(notesHtml).toContain("script-src 'self'");
      expect(notesHtml).toContain("object-src 'none'");
    });

    test('should include search input validation', () => {
      const notesHtml = readHtmlFile('notes.html');
      const dom = new JSDOM(notesHtml);
      const document = dom.window.document;
      
      const searchInput = document.getElementById('search-input');
      expect(searchInput).toBeTruthy();
      expect(searchInput.getAttribute('maxlength')).toBe('100');
      expect(searchInput.getAttribute('aria-label')).toBe('Search notes');
    });

    test('should sanitize note content in display', () => {
      const notesJs = readJsFile('notes.js');
      
      expect(notesJs).toContain('sanitizeInput');
      expect(notesJs).toContain('authUtils.sanitizeInput');
      expect(notesJs).toContain('createNoteHtml');
    });

    test('should include secure delete confirmation', () => {
      const notesHtml = readHtmlFile('notes.html');
      const dom = new JSDOM(notesHtml);
      const document = dom.window.document;
      
      const deleteModal = document.getElementById('delete-modal');
      const confirmDeleteBtn = document.getElementById('confirm-delete');
      const cancelDeleteBtn = document.getElementById('cancel-delete');
      
      expect(deleteModal).toBeTruthy();
      expect(confirmDeleteBtn).toBeTruthy();
      expect(cancelDeleteBtn).toBeTruthy();
      expect(deleteModal.className).toContain('modal');
    });

    test('should include pagination security', () => {
      const notesJs = readJsFile('notes.js');
      
      expect(notesJs).toContain('updatePagination');
      expect(notesJs).toContain('currentPage');
      expect(notesJs).toContain('totalPages');
      expect(notesJs).toContain('disabled');
    });
  });

  describe('Note Editor Security', () => {
    test('should include proper CSP headers in editor', () => {
      const editorHtml = readHtmlFile('note-editor.html');
      
      expect(editorHtml).toContain('Content-Security-Policy');
      expect(editorHtml).toContain("default-src 'self'");
      expect(editorHtml).toContain("script-src 'self'");
      expect(editorHtml).toContain("object-src 'none'");
    });

    test('should include input validation attributes', () => {
      const editorHtml = readHtmlFile('note-editor.html');
      const dom = new JSDOM(editorHtml);
      const document = dom.window.document;
      
      const titleInput = document.getElementById('note-title');
      const contentTextarea = document.getElementById('note-content');
      
      expect(titleInput.getAttribute('maxlength')).toBe('200');
      expect(titleInput.hasAttribute('required')).toBe(true);
      expect(contentTextarea.getAttribute('maxlength')).toBe('10000');
      expect(contentTextarea.hasAttribute('required')).toBe(true);
    });

    test('should include CSRF token input', () => {
      const editorHtml = readHtmlFile('note-editor.html');
      const dom = new JSDOM(editorHtml);
      const document = dom.window.document;
      
      const csrfInput = document.getElementById('csrf-token');
      expect(csrfInput).toBeTruthy();
      expect(csrfInput.getAttribute('type')).toBe('hidden');
      expect(csrfInput.getAttribute('name')).toBe('_csrf');
    });

    test('should include content length validation', () => {
      const editorJs = readJsFile('note-editor.js');
      
      expect(editorJs).toContain('validateTitle');
      expect(editorJs).toContain('validateContent');
      expect(editorJs).toContain('title.length > 200');
      expect(editorJs).toContain('content.length > 10000');
    });

    test('should sanitize input before submission', () => {
      const editorJs = readJsFile('note-editor.js');
      
      expect(editorJs).toContain('sanitizeInput');
      expect(editorJs).toContain('authUtils.sanitizeInput');
      expect(editorJs).toContain('handleSubmit');
    });

    test('should include unsaved changes warning', () => {
      const editorJs = readJsFile('note-editor.js');
      
      expect(editorJs).toContain('hasUnsavedChanges');
      expect(editorJs).toContain('beforeunload');
      expect(editorJs).toContain('You have unsaved changes');
    });

    test('should include character count display', () => {
      const editorHtml = readHtmlFile('note-editor.html');
      const dom = new JSDOM(editorHtml);
      const document = dom.window.document;
      
      const charCount = document.getElementById('char-count');
      const contentHelp = document.getElementById('content-help');
      
      expect(charCount).toBeTruthy();
      expect(contentHelp).toBeTruthy();
      expect(contentHelp.textContent).toContain('10,000 characters');
    });
  });

  describe('XSS Prevention in Notes Interface', () => {
    test('should prevent script injection in note titles', () => {
      const notesJs = readJsFile('notes.js');
      
      // Check that content is sanitized before display
      expect(notesJs).toContain('authUtils.sanitizeInput(note.title');
      expect(notesJs).toContain('createNoteHtml');
    });

    test('should prevent script injection in note content', () => {
      const notesJs = readJsFile('notes.js');
      
      // Check that content preview is sanitized
      expect(notesJs).toContain('authUtils.sanitizeInput(this.truncateText(note.content');
      expect(notesJs).toContain('note-preview');
    });

    test('should include proper output encoding', () => {
      const dashboardJs = readJsFile('dashboard.js');
      const notesJs = readJsFile('notes.js');
      
      // Both should sanitize output
      expect(dashboardJs).toContain('sanitizeInput');
      expect(notesJs).toContain('sanitizeInput');
    });
  });

  describe('Authentication and Authorization', () => {
    test('should check authentication on all pages', () => {
      const dashboardJs = readJsFile('dashboard.js');
      const notesJs = readJsFile('notes.js');
      const editorJs = readJsFile('note-editor.js');
      
      expect(dashboardJs).toContain('checkAuthentication');
      expect(notesJs).toContain('checkAuthentication');
      expect(editorJs).toContain('checkAuthentication');
    });

    test('should redirect to login when not authenticated', () => {
      const dashboardJs = readJsFile('dashboard.js');
      const notesJs = readJsFile('notes.js');
      const editorJs = readJsFile('note-editor.js');
      
      expect(dashboardJs).toContain('window.location.href = \'/login\'');
      expect(notesJs).toContain('window.location.href = \'/login\'');
      expect(editorJs).toContain('window.location.href = \'/login\'');
    });

    test('should include secure logout on all pages', () => {
      const dashboardJs = readJsFile('dashboard.js');
      const notesJs = readJsFile('notes.js');
      const editorJs = readJsFile('note-editor.js');
      
      expect(dashboardJs).toContain('handleLogout');
      expect(notesJs).toContain('handleLogout');
      expect(editorJs).toContain('handleLogout');
    });
  });

  describe('Input Validation and Sanitization', () => {
    test('should validate search input length', () => {
      const notesHtml = readHtmlFile('notes.html');
      const dom = new JSDOM(notesHtml);
      const document = dom.window.document;
      
      const searchInput = document.getElementById('search-input');
      expect(searchInput.getAttribute('maxlength')).toBe('100');
    });

    test('should validate note title length', () => {
      const editorHtml = readHtmlFile('note-editor.html');
      const dom = new JSDOM(editorHtml);
      const document = dom.window.document;
      
      const titleInput = document.getElementById('note-title');
      expect(titleInput.getAttribute('maxlength')).toBe('200');
    });

    test('should validate note content length', () => {
      const editorHtml = readHtmlFile('note-editor.html');
      const dom = new JSDOM(editorHtml);
      const document = dom.window.document;
      
      const contentTextarea = document.getElementById('note-content');
      expect(contentTextarea.getAttribute('maxlength')).toBe('10000');
    });

    test('should include client-side validation functions', () => {
      const editorJs = readJsFile('note-editor.js');
      
      expect(editorJs).toContain('validateTitle');
      expect(editorJs).toContain('validateContent');
      expect(editorJs).toContain('isFormValid');
    });
  });

  describe('Error Handling', () => {
    test('should include error display elements', () => {
      const dashboardHtml = readHtmlFile('dashboard.html');
      const notesHtml = readHtmlFile('notes.html');
      const editorHtml = readHtmlFile('note-editor.html');
      
      [dashboardHtml, notesHtml, editorHtml].forEach(html => {
        const dom = new JSDOM(html);
        const document = dom.window.document;
        
        const errorMessage = document.getElementById('error-message');
        const successMessage = document.getElementById('success-message');
        
        expect(errorMessage).toBeTruthy();
        expect(successMessage).toBeTruthy();
        expect(errorMessage.className).toContain('alert-error');
        expect(successMessage.className).toContain('alert-success');
      });
    });

    test('should handle different error types securely', () => {
      const editorJs = readJsFile('note-editor.js');
      
      expect(editorJs).toContain('handleSaveError');
      expect(editorJs).toContain('case 400:');
      expect(editorJs).toContain('case 401:');
      expect(editorJs).toContain('case 403:');
      expect(editorJs).toContain('case 404:');
    });
  });

  describe('Accessibility', () => {
    test('should include proper form labels', () => {
      const editorHtml = readHtmlFile('note-editor.html');
      const dom = new JSDOM(editorHtml);
      const document = dom.window.document;
      
      const titleLabel = document.querySelector('label[for="note-title"]');
      const contentLabel = document.querySelector('label[for="note-content"]');
      
      expect(titleLabel).toBeTruthy();
      expect(contentLabel).toBeTruthy();
      expect(titleLabel.textContent).toContain('Title');
      expect(contentLabel.textContent).toContain('Content');
    });

    test('should include ARIA attributes', () => {
      const editorHtml = readHtmlFile('note-editor.html');
      const notesHtml = readHtmlFile('notes.html');
      
      const editorDom = new JSDOM(editorHtml);
      const notesDom = new JSDOM(notesHtml);
      
      // Editor ARIA attributes
      const titleInput = editorDom.window.document.getElementById('note-title');
      const contentTextarea = editorDom.window.document.getElementById('note-content');
      
      expect(titleInput.getAttribute('aria-describedby')).toContain('title-error');
      expect(contentTextarea.getAttribute('aria-describedby')).toContain('content-error');
      
      // Search ARIA attributes
      const searchInput = notesDom.window.document.getElementById('search-input');
      expect(searchInput.getAttribute('aria-label')).toBe('Search notes');
    });

    test('should include help text for form fields', () => {
      const editorHtml = readHtmlFile('note-editor.html');
      const dom = new JSDOM(editorHtml);
      const document = dom.window.document;
      
      const titleHelp = document.getElementById('title-help');
      const contentHelp = document.getElementById('content-help');
      
      expect(titleHelp).toBeTruthy();
      expect(contentHelp).toBeTruthy();
      expect(titleHelp.className).toContain('field-help');
      expect(contentHelp.className).toContain('field-help');
    });
  });

  describe('Security Features', () => {
    test('should include autosave with security considerations', () => {
      const editorJs = readJsFile('note-editor.js');
      
      expect(editorJs).toContain('performAutosave');
      expect(editorJs).toContain('scheduleAutosave');
      expect(editorJs).toContain('isEditing');
      expect(editorJs).toContain('hasUnsavedChanges');
    });

    test('should include secure request handling', () => {
      const dashboardJs = readJsFile('dashboard.js');
      const notesJs = readJsFile('notes.js');
      const editorJs = readJsFile('note-editor.js');
      
      [dashboardJs, notesJs, editorJs].forEach(js => {
        expect(js).toContain('secureRequest');
        expect(js).toContain('authUtils.secureRequest');
      });
    });

    test('should include proper modal security', () => {
      const notesHtml = readHtmlFile('notes.html');
      const dom = new JSDOM(notesHtml);
      const document = dom.window.document;
      
      const modal = document.getElementById('delete-modal');
      expect(modal).toBeTruthy();
      expect(modal.className).toContain('modal');
      expect(modal.style.display).toBe('none');
    });
  });
});