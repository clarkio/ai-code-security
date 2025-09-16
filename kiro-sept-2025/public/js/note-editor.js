/**
 * Note editor functionality with secure input validation and XSS prevention
 */

class NoteEditor {
    constructor() {
        this.isEditing = false;
        this.noteId = null;
        this.hasUnsavedChanges = false;
        this.autosaveTimeout = null;
        this.init();
    }

    init() {
        document.addEventListener('DOMContentLoaded', () => {
            this.setupElements();
            this.setupEventListeners();
            this.setupValidation();
            this.checkAuthentication();
            this.loadNoteIfEditing();
        });
    }

    setupElements() {
        this.form = document.getElementById('note-form');
        this.titleInput = document.getElementById('note-title');
        this.contentTextarea = document.getElementById('note-content');
        this.submitBtn = document.getElementById('submit-btn');
        this.cancelBtn = document.getElementById('cancel-btn');
        this.cancelFormBtn = document.getElementById('cancel-form-btn');
        this.charCountElement = document.getElementById('char-count');
        this.autosaveStatus = document.getElementById('autosave-status');
        this.editorTitle = document.getElementById('editor-title');
        this.noteIdInput = document.getElementById('note-id');
    }

    setupEventListeners() {
        // Form submission
        if (this.form) {
            this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        }

        // Cancel buttons
        [this.cancelBtn, this.cancelFormBtn].forEach(btn => {
            if (btn) {
                btn.addEventListener('click', (e) => {
                    e.preventDefault();
                    this.handleCancel();
                });
            }
        });

        // Input validation and character counting
        if (this.titleInput) {
            this.titleInput.addEventListener('input', () => {
                this.validateTitle();
                this.markAsChanged();
            });
            this.titleInput.addEventListener('blur', () => this.validateTitle());
        }

        if (this.contentTextarea) {
            this.contentTextarea.addEventListener('input', () => {
                this.updateCharCount();
                this.validateContent();
                this.markAsChanged();
                this.scheduleAutosave();
            });
            this.contentTextarea.addEventListener('blur', () => this.validateContent());
        }

        // Logout functionality
        const logoutLink = document.getElementById('logout-link');
        if (logoutLink) {
            logoutLink.addEventListener('click', (e) => {
                e.preventDefault();
                this.handleLogout();
            });
        }

        // Warn about unsaved changes
        window.addEventListener('beforeunload', (e) => {
            if (this.hasUnsavedChanges) {
                e.preventDefault();
                e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
                return e.returnValue;
            }
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            // Ctrl+S or Cmd+S to save
            if ((e.ctrlKey || e.metaKey) && e.key === 's') {
                e.preventDefault();
                this.handleSubmit(e);
            }
        });
    }

    setupValidation() {
        // Set up HTML5 validation attributes
        if (this.titleInput) {
            this.titleInput.setAttribute('maxlength', '200');
            this.titleInput.setAttribute('title', 'Title must be between 1 and 200 characters');
        }

        if (this.contentTextarea) {
            this.contentTextarea.setAttribute('maxlength', '10000');
            this.contentTextarea.setAttribute('title', 'Content must be between 1 and 10,000 characters');
        }
    }

    async checkAuthentication() {
        if (typeof authUtils !== 'undefined') {
            try {
                const isAuthenticated = await authUtils.checkAuthStatus();
                if (!isAuthenticated) {
                    window.location.href = '/login';
                    return;
                }
            } catch (error) {
                console.error('Authentication check failed:', error);
                window.location.href = '/login';
                return;
            }
        }
    }

    loadNoteIfEditing() {
        // Check if we're editing an existing note
        const urlPath = window.location.pathname;
        const editMatch = urlPath.match(/\/notes\/edit\/(.+)$/);
        
        if (editMatch) {
            this.isEditing = true;
            this.noteId = editMatch[1];
            this.loadNote(this.noteId);
            
            if (this.editorTitle) {
                this.editorTitle.textContent = 'Edit Note';
            }
            
            if (this.noteIdInput) {
                this.noteIdInput.value = this.noteId;
            }
        }
    }

    async loadNote(noteId) {
        try {
            const response = await authUtils.secureRequest(`/api/notes/${noteId}`, {
                method: 'GET'
            });

            if (response.ok) {
                const note = await response.json();
                this.populateForm(note);
            } else {
                authUtils.showError('Failed to load note. Redirecting to notes list...');
                setTimeout(() => {
                    window.location.href = '/notes';
                }, 2000);
            }
        } catch (error) {
            console.error('Failed to load note:', error);
            authUtils.showError('Failed to load note. Please try again.');
        }
    }

    populateForm(note) {
        if (this.titleInput) {
            this.titleInput.value = note.title || '';
        }
        
        if (this.contentTextarea) {
            this.contentTextarea.value = note.content || '';
            this.updateCharCount();
        }
        
        // Mark as not changed since we just loaded
        this.hasUnsavedChanges = false;
    }

    async handleSubmit(event) {
        event.preventDefault();
        
        // Clear previous messages
        authUtils.hideMessages();
        this.clearAllFieldErrors();

        // Validate form
        if (!this.isFormValid()) {
            authUtils.showError('Please fix the errors below before saving.');
            return;
        }

        // Set loading state
        authUtils.setButtonLoading('submit-btn', true);

        try {
            const formData = new FormData(this.form);
            const noteData = {
                title: authUtils.sanitizeInput(formData.get('title')),
                content: formData.get('content'), // Don't sanitize content as it may contain intentional formatting
                _csrf: formData.get('_csrf')
            };

            const url = this.isEditing ? `/api/notes/${this.noteId}` : '/api/notes';
            const method = this.isEditing ? 'PUT' : 'POST';

            const response = await authUtils.secureRequest(url, {
                method: method,
                body: JSON.stringify(noteData)
            });

            const result = await response.json();

            if (response.ok) {
                // Success
                const action = this.isEditing ? 'updated' : 'created';
                authUtils.showSuccess(`Note ${action} successfully! Redirecting...`);
                
                // Mark as saved
                this.hasUnsavedChanges = false;
                
                // Redirect after short delay
                setTimeout(() => {
                    window.location.href = '/notes';
                }, 1500);
            } else {
                // Handle different error types
                this.handleSaveError(response.status, result);
            }
        } catch (error) {
            console.error('Save error:', error);
            authUtils.showError('Network error. Please check your connection and try again.');
        } finally {
            authUtils.setButtonLoading('submit-btn', false);
        }
    }

    handleSaveError(status, result) {
        switch (status) {
            case 400:
                // Validation errors
                if (result.errors && Array.isArray(result.errors)) {
                    result.errors.forEach(error => {
                        if (error.field) {
                            authUtils.showFieldError(error.field, error.message);
                        } else {
                            authUtils.showError(error.message);
                        }
                    });
                } else {
                    authUtils.showError(result.error?.message || 'Invalid input. Please check your information.');
                }
                break;
                
            case 401:
                authUtils.showError('You are not authorized to perform this action. Please log in again.');
                setTimeout(() => {
                    window.location.href = '/login';
                }, 2000);
                break;
                
            case 403:
                authUtils.showError('You do not have permission to access this note.');
                break;
                
            case 404:
                authUtils.showError('Note not found. It may have been deleted.');
                setTimeout(() => {
                    window.location.href = '/notes';
                }, 2000);
                break;
                
            case 413:
                authUtils.showError('Note content is too large. Please reduce the size.');
                break;
                
            case 500:
                authUtils.showError('Server error. Please try again later.');
                break;
                
            default:
                authUtils.showError(result.error?.message || 'Failed to save note. Please try again.');
        }
    }

    handleCancel() {
        if (this.hasUnsavedChanges) {
            const confirmLeave = confirm('You have unsaved changes. Are you sure you want to leave?');
            if (!confirmLeave) {
                return;
            }
        }
        
        window.location.href = '/notes';
    }

    validateTitle() {
        const title = this.titleInput.value.trim();
        
        if (!title) {
            authUtils.showFieldError('title', 'Title is required');
            return false;
        }
        
        if (title.length > 200) {
            authUtils.showFieldError('title', 'Title must be 200 characters or less');
            return false;
        }
        
        authUtils.hideFieldError('title');
        return true;
    }

    validateContent() {
        const content = this.contentTextarea.value.trim();
        
        if (!content) {
            authUtils.showFieldError('content', 'Content is required');
            return false;
        }
        
        if (content.length > 10000) {
            authUtils.showFieldError('content', 'Content must be 10,000 characters or less');
            return false;
        }
        
        authUtils.hideFieldError('content');
        return true;
    }

    isFormValid() {
        const titleValid = this.validateTitle();
        const contentValid = this.validateContent();
        
        return titleValid && contentValid;
    }

    clearAllFieldErrors() {
        ['title', 'content'].forEach(field => {
            authUtils.hideFieldError(field);
        });
    }

    updateCharCount() {
        if (this.charCountElement && this.contentTextarea) {
            const count = this.contentTextarea.value.length;
            this.charCountElement.textContent = count.toLocaleString();
            
            // Change color based on usage
            if (count > 9000) {
                this.charCountElement.style.color = '#dc3545'; // Red
            } else if (count > 7500) {
                this.charCountElement.style.color = '#fd7e14'; // Orange
            } else {
                this.charCountElement.style.color = '#6c757d'; // Default
            }
        }
    }

    markAsChanged() {
        this.hasUnsavedChanges = true;
    }

    scheduleAutosave() {
        // Clear existing timeout
        if (this.autosaveTimeout) {
            clearTimeout(this.autosaveTimeout);
        }

        // Only autosave for existing notes
        if (!this.isEditing) return;

        // Schedule autosave after 2 seconds of inactivity
        this.autosaveTimeout = setTimeout(() => {
            this.performAutosave();
        }, 2000);
    }

    async performAutosave() {
        if (!this.isEditing || !this.hasUnsavedChanges) return;

        try {
            const noteData = {
                title: authUtils.sanitizeInput(this.titleInput.value),
                content: this.contentTextarea.value,
                _csrf: authUtils.csrfToken
            };

            const response = await authUtils.secureRequest(`/api/notes/${this.noteId}`, {
                method: 'PUT',
                body: JSON.stringify(noteData)
            });

            if (response.ok) {
                this.showAutosaveStatus('Draft saved');
                this.hasUnsavedChanges = false;
            }
        } catch (error) {
            console.error('Autosave failed:', error);
            // Don't show error to user for autosave failures
        }
    }

    showAutosaveStatus(message) {
        if (this.autosaveStatus) {
            const statusText = this.autosaveStatus.querySelector('#autosave-text');
            if (statusText) {
                statusText.textContent = message;
            }
            
            this.autosaveStatus.style.display = 'block';
            
            // Hide after 3 seconds
            setTimeout(() => {
                this.autosaveStatus.style.display = 'none';
            }, 3000);
        }
    }

    async handleLogout() {
        if (this.hasUnsavedChanges) {
            const confirmLogout = confirm('You have unsaved changes. Are you sure you want to log out?');
            if (!confirmLogout) {
                return;
            }
        }

        if (typeof authUtils !== 'undefined') {
            try {
                const response = await authUtils.secureRequest('/api/auth/logout', {
                    method: 'POST'
                });
                
                if (response.ok) {
                    authUtils.showSuccess('Logged out successfully. Redirecting...');
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 1000);
                } else {
                    console.error('Logout failed');
                    window.location.href = '/';
                }
            } catch (error) {
                console.error('Logout error:', error);
                window.location.href = '/';
            }
        }
    }
}

// Initialize note editor
const noteEditor = new NoteEditor();