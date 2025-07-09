// Secure Notes App Frontend
(function() {
    'use strict';

    // State management
    const state = {
        isAuthenticated: false,
        user: null,
        csrfToken: null,
        currentPage: 1,
        currentView: 'public', // 'public' or 'my'
        editingNoteId: null
    };

    // DOM elements
    const elements = {
        // Navigation
        publicNotesBtn: document.getElementById('publicNotesBtn'),
        myNotesBtn: document.getElementById('myNotesBtn'),
        loginBtn: document.getElementById('loginBtn'),
        registerBtn: document.getElementById('registerBtn'),
        logoutBtn: document.getElementById('logoutBtn'),
        
        // Containers
        authContainer: document.getElementById('authContainer'),
        notesContainer: document.getElementById('notesContainer'),
        noteFormContainer: document.getElementById('noteFormContainer'),
        notesListContainer: document.getElementById('notesListContainer'),
        
        // Forms
        loginForm: document.getElementById('loginForm'),
        registerForm: document.getElementById('registerForm'),
        noteForm: document.getElementById('noteForm'),
        
        // Other elements
        loading: document.getElementById('loading'),
        notesList: document.getElementById('notesList'),
        pagination: document.getElementById('pagination'),
        createNoteBtn: document.getElementById('createNoteBtn'),
        notesTitle: document.getElementById('notesTitle'),
        searchInput: document.getElementById('searchInput'),
        tagFilter: document.getElementById('tagFilter'),
        
        // Form inputs
        noteId: document.getElementById('noteId'),
        noteTitle: document.getElementById('noteTitle'),
        noteContent: document.getElementById('noteContent'),
        noteTags: document.getElementById('noteTags'),
        notePublic: document.getElementById('notePublic'),
        noteFormTitle: document.getElementById('noteFormTitle'),
        cancelNoteBtn: document.getElementById('cancelNoteBtn')
    };

    // API configuration
    const API = {
        baseURL: '/api',
        
        async request(endpoint, options = {}) {
            const url = `${this.baseURL}${endpoint}`;
            const config = {
                ...options,
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': state.csrfToken,
                    ...options.headers
                },
                credentials: 'same-origin'
            };

            if (options.body && typeof options.body === 'object') {
                config.body = JSON.stringify(options.body);
            }

            try {
                showLoading();
                const response = await fetch(url, config);
                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || 'Request failed');
                }

                // Update CSRF token if provided
                if (data.csrfToken) {
                    state.csrfToken = data.csrfToken;
                    updateCSRFToken(data.csrfToken);
                }

                return data;
            } catch (error) {
                console.error('API request failed:', error);
                throw error;
            } finally {
                hideLoading();
            }
        }
    };

    // Utility functions
    function showLoading() {
        elements.loading.style.display = 'flex';
    }

    function hideLoading() {
        elements.loading.style.display = 'none';
    }

    function showError(elementId, message) {
        const errorElement = document.getElementById(elementId);
        if (errorElement) {
            errorElement.textContent = message;
            errorElement.style.display = 'block';
            setTimeout(() => {
                errorElement.style.display = 'none';
            }, 5000);
        }
    }

    function updateCSRFToken(token) {
        state.csrfToken = token;
        document.querySelector('meta[name="csrf-token"]').setAttribute('content', token);
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    }

    // Authentication functions
    async function initializeAuth() {
        try {
            // Get CSRF token
            const csrfData = await API.request('/auth/csrf');
            updateCSRFToken(csrfData.csrfToken);

            // Check if user is logged in
            const profileData = await API.request('/auth/profile');
            state.isAuthenticated = true;
            state.user = profileData.user;
            updateUIForAuth(true);
        } catch (error) {
            state.isAuthenticated = false;
            state.user = null;
            updateUIForAuth(false);
        }
    }

    function updateUIForAuth(isAuthenticated) {
        if (isAuthenticated) {
            elements.loginBtn.style.display = 'none';
            elements.registerBtn.style.display = 'none';
            elements.logoutBtn.style.display = 'block';
            elements.myNotesBtn.style.display = 'block';
            elements.createNoteBtn.style.display = 'block';
        } else {
            elements.loginBtn.style.display = 'block';
            elements.registerBtn.style.display = 'block';
            elements.logoutBtn.style.display = 'none';
            elements.myNotesBtn.style.display = 'none';
            elements.createNoteBtn.style.display = 'none';
        }
    }

    async function handleLogin(event) {
        event.preventDefault();
        const formData = new FormData(event.target);
        
        try {
            const data = await API.request('/auth/login', {
                method: 'POST',
                body: {
                    username: formData.get('username'),
                    password: formData.get('password')
                }
            });

            state.isAuthenticated = true;
            state.user = data.user;
            updateUIForAuth(true);
            hideAuthForms();
            loadNotes();
        } catch (error) {
            showError('loginError', error.message);
        }
    }

    async function handleRegister(event) {
        event.preventDefault();
        const formData = new FormData(event.target);
        
        if (formData.get('password') !== formData.get('confirmPassword')) {
            showError('registerError', 'Passwords do not match');
            return;
        }

        try {
            const data = await API.request('/auth/register', {
                method: 'POST',
                body: {
                    username: formData.get('username'),
                    email: formData.get('email'),
                    password: formData.get('password'),
                    confirmPassword: formData.get('confirmPassword')
                }
            });

            state.isAuthenticated = true;
            state.user = data.user;
            updateUIForAuth(true);
            hideAuthForms();
            loadNotes();
        } catch (error) {
            showError('registerError', error.message);
        }
    }

    async function handleLogout() {
        try {
            await API.request('/auth/logout', {
                method: 'POST'
            });

            state.isAuthenticated = false;
            state.user = null;
            state.currentView = 'public';
            updateUIForAuth(false);
            loadNotes();
        } catch (error) {
            console.error('Logout failed:', error);
        }
    }

    // Note functions
    async function loadNotes(page = 1) {
        try {
            const params = new URLSearchParams({
                page: page,
                limit: 10
            });

            const search = elements.searchInput.value.trim();
            if (search) {
                params.append('search', search);
            }

            const tag = elements.tagFilter.value;
            if (tag) {
                params.append('tag', tag);
            }

            const endpoint = state.currentView === 'my' 
                ? `/notes/my?${params}` 
                : `/notes/public?${params}`;

            const data = await API.request(endpoint);
            
            displayNotes(data.notes);
            displayPagination(data.pagination);
            
            // Update tags filter if viewing my notes
            if (state.currentView === 'my' && page === 1) {
                await loadTags();
            }
        } catch (error) {
            console.error('Failed to load notes:', error);
            elements.notesList.innerHTML = '<p class="error-message">Failed to load notes</p>';
        }
    }

    function displayNotes(notes) {
        if (notes.length === 0) {
            elements.notesList.innerHTML = '<p>No notes found</p>';
            return;
        }

        elements.notesList.innerHTML = notes.map(note => `
            <div class="note-card" data-note-id="${escapeHtml(note.id)}">
                <div class="note-header">
                    <div>
                        <h3 class="note-title">${escapeHtml(note.title)}</h3>
                        <p class="note-meta">
                            By ${escapeHtml(note.author?.username || 'Unknown')} • 
                            ${formatDate(note.created_at)}
                            ${note.is_public ? ' • Public' : ' • Private'}
                        </p>
                    </div>
                </div>
                <div class="note-content">
                    ${note.content}
                </div>
                ${note.tags && note.tags.length > 0 ? `
                    <div class="note-tags">
                        ${note.tags.map(tag => `
                            <span class="note-tag">${escapeHtml(tag)}</span>
                        `).join('')}
                    </div>
                ` : ''}
                ${state.isAuthenticated && note.user_id === state.user?.id ? `
                    <div class="note-actions">
                        <button class="btn btn-primary btn-edit" data-note-id="${escapeHtml(note.id)}">Edit</button>
                        <button class="btn btn-danger btn-delete" data-note-id="${escapeHtml(note.id)}">Delete</button>
                    </div>
                ` : ''}
            </div>
        `).join('');

        // Add event listeners for edit and delete buttons
        document.querySelectorAll('.btn-edit').forEach(btn => {
            btn.addEventListener('click', () => editNote(btn.dataset.noteId));
        });

        document.querySelectorAll('.btn-delete').forEach(btn => {
            btn.addEventListener('click', () => deleteNote(btn.dataset.noteId));
        });
    }

    function displayPagination(pagination) {
        if (!pagination || pagination.pages <= 1) {
            elements.pagination.innerHTML = '';
            return;
        }

        const { page, pages } = pagination;
        let html = '';

        // Previous button
        html += `<button ${page === 1 ? 'disabled' : ''} data-page="${page - 1}">Previous</button>`;

        // Page numbers
        for (let i = 1; i <= pages; i++) {
            if (i === 1 || i === pages || (i >= page - 2 && i <= page + 2)) {
                html += `<button class="${i === page ? 'active' : ''}" data-page="${i}">${i}</button>`;
            } else if (i === page - 3 || i === page + 3) {
                html += '<span>...</span>';
            }
        }

        // Next button
        html += `<button ${page === pages ? 'disabled' : ''} data-page="${page + 1}">Next</button>`;

        elements.pagination.innerHTML = html;

        // Add event listeners
        elements.pagination.querySelectorAll('button:not([disabled])').forEach(btn => {
            btn.addEventListener('click', () => {
                state.currentPage = parseInt(btn.dataset.page);
                loadNotes(state.currentPage);
            });
        });
    }

    async function loadTags() {
        try {
            const data = await API.request('/notes/tags/all');
            const currentTag = elements.tagFilter.value;
            
            elements.tagFilter.innerHTML = '<option value="">All Tags</option>';
            data.tags.forEach(tag => {
                const option = document.createElement('option');
                option.value = tag;
                option.textContent = tag;
                if (tag === currentTag) {
                    option.selected = true;
                }
                elements.tagFilter.appendChild(option);
            });
        } catch (error) {
            console.error('Failed to load tags:', error);
        }
    }

    async function handleNoteSubmit(event) {
        event.preventDefault();
        const formData = new FormData(event.target);
        
        const noteData = {
            title: formData.get('title'),
            content: formData.get('content'),
            is_public: formData.get('is_public') === 'on',
            tags: formData.get('tags').split(',').map(tag => tag.trim()).filter(Boolean)
        };

        try {
            if (state.editingNoteId) {
                await API.request(`/notes/${state.editingNoteId}`, {
                    method: 'PUT',
                    body: noteData
                });
            } else {
                await API.request('/notes', {
                    method: 'POST',
                    body: noteData
                });
            }

            hideNoteForm();
            loadNotes(state.currentPage);
        } catch (error) {
            showError('noteError', error.message);
        }
    }

    async function editNote(noteId) {
        try {
            const data = await API.request(`/notes/${noteId}`);
            const note = data.note;

            state.editingNoteId = noteId;
            elements.noteFormTitle.textContent = 'Edit Note';
            elements.noteId.value = noteId;
            elements.noteTitle.value = note.title;
            elements.noteContent.value = note.content;
            elements.noteTags.value = note.tags ? note.tags.join(', ') : '';
            elements.notePublic.checked = note.is_public;

            showNoteForm();
        } catch (error) {
            console.error('Failed to load note for editing:', error);
        }
    }

    async function deleteNote(noteId) {
        if (!confirm('Are you sure you want to delete this note?')) {
            return;
        }

        try {
            await API.request(`/notes/${noteId}`, {
                method: 'DELETE'
            });
            loadNotes(state.currentPage);
        } catch (error) {
            console.error('Failed to delete note:', error);
        }
    }

    // UI functions
    function showAuthForm(formType) {
        hideNoteForm();
        elements.authContainer.style.display = 'block';
        elements.notesContainer.style.display = 'none';
        
        if (formType === 'login') {
            elements.loginForm.style.display = 'block';
            elements.registerForm.style.display = 'none';
        } else {
            elements.loginForm.style.display = 'none';
            elements.registerForm.style.display = 'block';
        }
    }

    function hideAuthForms() {
        elements.authContainer.style.display = 'none';
        elements.notesContainer.style.display = 'block';
        elements.loginForm.style.display = 'none';
        elements.registerForm.style.display = 'none';
    }

    function showNoteForm() {
        elements.noteFormContainer.style.display = 'block';
        elements.notesListContainer.style.display = 'none';
    }

    function hideNoteForm() {
        elements.noteFormContainer.style.display = 'none';
        elements.notesListContainer.style.display = 'block';
        elements.noteForm.reset();
        state.editingNoteId = null;
        elements.noteFormTitle.textContent = 'Create Note';
    }

    // Event listeners
    function initializeEventListeners() {
        // Navigation
        elements.publicNotesBtn.addEventListener('click', () => {
            state.currentView = 'public';
            state.currentPage = 1;
            elements.notesTitle.textContent = 'Public Notes';
            hideAuthForms();
            hideNoteForm();
            loadNotes();
        });

        elements.myNotesBtn.addEventListener('click', () => {
            state.currentView = 'my';
            state.currentPage = 1;
            elements.notesTitle.textContent = 'My Notes';
            hideAuthForms();
            hideNoteForm();
            loadNotes();
        });

        elements.loginBtn.addEventListener('click', () => showAuthForm('login'));
        elements.registerBtn.addEventListener('click', () => showAuthForm('register'));
        elements.logoutBtn.addEventListener('click', handleLogout);

        // Forms
        elements.loginForm.addEventListener('submit', handleLogin);
        elements.registerForm.addEventListener('submit', handleRegister);
        elements.noteForm.addEventListener('submit', handleNoteSubmit);

        // Note actions
        elements.createNoteBtn.addEventListener('click', () => {
            state.editingNoteId = null;
            elements.noteFormTitle.textContent = 'Create Note';
            showNoteForm();
        });

        elements.cancelNoteBtn.addEventListener('click', hideNoteForm);

        // Search and filter
        let searchTimeout;
        elements.searchInput.addEventListener('input', () => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                state.currentPage = 1;
                loadNotes();
            }, 300);
        });

        elements.tagFilter.addEventListener('change', () => {
            state.currentPage = 1;
            loadNotes();
        });
    }

    // Initialize app
    async function init() {
        await initializeAuth();
        initializeEventListeners();
        loadNotes();
    }

    // Start the app when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();