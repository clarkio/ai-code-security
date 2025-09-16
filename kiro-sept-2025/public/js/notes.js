/**
 * Notes management functionality with secure content rendering
 */

class NotesManager {
    constructor() {
        this.notes = [];
        this.currentPage = 1;
        this.totalPages = 1;
        this.searchQuery = '';
        this.noteToDelete = null;
        this.init();
    }

    init() {
        document.addEventListener('DOMContentLoaded', () => {
            this.setupEventListeners();
            this.loadNotes();
            this.checkAuthentication();
        });
    }

    setupEventListeners() {
        // Logout functionality
        const logoutLink = document.getElementById('logout-link');
        if (logoutLink) {
            logoutLink.addEventListener('click', (e) => {
                e.preventDefault();
                this.handleLogout();
            });
        }

        // Refresh notes
        const refreshBtn = document.getElementById('refresh-notes');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.loadNotes();
            });
        }

        // Search functionality
        const searchBtn = document.getElementById('search-btn');
        const searchInput = document.getElementById('search-input');
        const clearSearchBtn = document.getElementById('clear-search');

        if (searchBtn && searchInput) {
            searchBtn.addEventListener('click', () => {
                this.performSearch();
            });

            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.performSearch();
                }
            });

            // Real-time search with debounce
            let searchTimeout;
            searchInput.addEventListener('input', () => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.performSearch();
                }, 500);
            });
        }

        if (clearSearchBtn) {
            clearSearchBtn.addEventListener('click', () => {
                this.clearSearch();
            });
        }

        // Pagination
        const prevPageBtn = document.getElementById('prev-page');
        const nextPageBtn = document.getElementById('next-page');

        if (prevPageBtn) {
            prevPageBtn.addEventListener('click', () => {
                if (this.currentPage > 1) {
                    this.currentPage--;
                    this.loadNotes();
                }
            });
        }

        if (nextPageBtn) {
            nextPageBtn.addEventListener('click', () => {
                if (this.currentPage < this.totalPages) {
                    this.currentPage++;
                    this.loadNotes();
                }
            });
        }

        // Delete modal
        const cancelDeleteBtn = document.getElementById('cancel-delete');
        const confirmDeleteBtn = document.getElementById('confirm-delete');

        if (cancelDeleteBtn) {
            cancelDeleteBtn.addEventListener('click', () => {
                this.hideDeleteModal();
            });
        }

        if (confirmDeleteBtn) {
            confirmDeleteBtn.addEventListener('click', () => {
                this.confirmDelete();
            });
        }

        // Close modal on background click
        const deleteModal = document.getElementById('delete-modal');
        if (deleteModal) {
            deleteModal.addEventListener('click', (e) => {
                if (e.target === deleteModal) {
                    this.hideDeleteModal();
                }
            });
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

    async loadNotes() {
        const loadingSpinner = document.getElementById('loading-spinner');
        const notesList = document.getElementById('notes-list');
        const emptyState = document.getElementById('empty-state');

        // Show loading
        if (loadingSpinner) loadingSpinner.style.display = 'block';
        if (notesList) notesList.style.display = 'none';
        if (emptyState) emptyState.style.display = 'none';

        try {
            const params = new URLSearchParams({
                page: this.currentPage,
                limit: 10
            });

            if (this.searchQuery) {
                params.append('search', this.searchQuery);
            }

            const response = await authUtils.secureRequest(`/api/notes?${params}`, {
                method: 'GET'
            });

            if (response.ok) {
                const data = await response.json();
                this.notes = data.notes || [];
                this.totalPages = data.totalPages || 1;
                this.displayNotes();
                this.updatePagination();
            } else {
                throw new Error('Failed to load notes');
            }
        } catch (error) {
            console.error('Failed to load notes:', error);
            authUtils.showError('Failed to load notes. Please try again.');
            this.displayNotes([]);
        } finally {
            if (loadingSpinner) loadingSpinner.style.display = 'none';
        }
    }

    displayNotes() {
        const notesList = document.getElementById('notes-list');
        const emptyState = document.getElementById('empty-state');

        if (!notesList || !emptyState) return;

        if (this.notes.length === 0) {
            notesList.style.display = 'none';
            emptyState.style.display = 'block';
            return;
        }

        emptyState.style.display = 'none';
        notesList.style.display = 'block';

        const notesHtml = this.notes.map(note => this.createNoteHtml(note)).join('');
        notesList.innerHTML = notesHtml;

        // Add event listeners to note actions
        this.attachNoteEventListeners();
    }

    createNoteHtml(note) {
        // Sanitize note data to prevent XSS
        const title = authUtils.sanitizeInput(note.title || 'Untitled');
        const preview = authUtils.sanitizeInput(this.truncateText(note.content || '', 200));
        const createdAt = this.formatDate(new Date(note.createdAt));
        const updatedAt = this.formatDate(new Date(note.updatedAt));
        const wordCount = this.getWordCount(note.content || '');

        return `
            <div class="note-item" data-note-id="${note.id}">
                <div class="note-header">
                    <h3 class="note-title">${title}</h3>
                    <div class="note-actions">
                        <a href="/notes/edit/${note.id}" class="btn btn-secondary">Edit</a>
                        <button type="button" class="btn btn-danger delete-note-btn" data-note-id="${note.id}">Delete</button>
                    </div>
                </div>
                <div class="note-preview">${preview}</div>
                <div class="note-meta">
                    <div class="note-stats">
                        <span>${wordCount} words</span>
                        <span>${note.content?.length || 0} characters</span>
                    </div>
                    <div>
                        <div class="note-date">Created: ${createdAt}</div>
                        <div class="note-date">Updated: ${updatedAt}</div>
                    </div>
                </div>
            </div>
        `;
    }

    attachNoteEventListeners() {
        // Delete buttons
        const deleteButtons = document.querySelectorAll('.delete-note-btn');
        deleteButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                const noteId = btn.getAttribute('data-note-id');
                this.showDeleteModal(noteId);
            });
        });
    }

    showDeleteModal(noteId) {
        this.noteToDelete = noteId;
        const modal = document.getElementById('delete-modal');
        if (modal) {
            modal.style.display = 'flex';
        }
    }

    hideDeleteModal() {
        this.noteToDelete = null;
        const modal = document.getElementById('delete-modal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    async confirmDelete() {
        if (!this.noteToDelete) return;

        try {
            const response = await authUtils.secureRequest(`/api/notes/${this.noteToDelete}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                authUtils.showSuccess('Note deleted successfully.');
                this.hideDeleteModal();
                this.loadNotes(); // Reload notes list
            } else {
                const error = await response.json();
                authUtils.showError(error.error?.message || 'Failed to delete note.');
            }
        } catch (error) {
            console.error('Delete error:', error);
            authUtils.showError('Failed to delete note. Please try again.');
        }
    }

    performSearch() {
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            this.searchQuery = searchInput.value.trim();
            this.currentPage = 1; // Reset to first page
            this.loadNotes();
        }
    }

    clearSearch() {
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            searchInput.value = '';
            this.searchQuery = '';
            this.currentPage = 1;
            this.loadNotes();
        }
    }

    updatePagination() {
        const pagination = document.getElementById('pagination');
        const prevPageBtn = document.getElementById('prev-page');
        const nextPageBtn = document.getElementById('next-page');
        const pageInfo = document.getElementById('page-info');

        if (!pagination) return;

        if (this.totalPages <= 1) {
            pagination.style.display = 'none';
            return;
        }

        pagination.style.display = 'flex';

        // Update page info
        if (pageInfo) {
            pageInfo.textContent = `Page ${this.currentPage} of ${this.totalPages}`;
        }

        // Update button states
        if (prevPageBtn) {
            prevPageBtn.disabled = this.currentPage <= 1;
        }

        if (nextPageBtn) {
            nextPageBtn.disabled = this.currentPage >= this.totalPages;
        }
    }

    truncateText(text, maxLength) {
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength) + '...';
    }

    getWordCount(text) {
        return text.trim().split(/\s+/).filter(word => word.length > 0).length;
    }

    formatDate(date) {
        if (!date || isNaN(date.getTime())) return 'Unknown';
        
        const now = new Date();
        const diffTime = Math.abs(now - date);
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

        if (diffDays === 1) {
            return 'Today';
        } else if (diffDays === 2) {
            return 'Yesterday';
        } else if (diffDays <= 7) {
            return `${diffDays - 1} days ago`;
        } else {
            return date.toLocaleDateString();
        }
    }

    async handleLogout() {
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

// Initialize notes manager
const notesManager = new NotesManager();