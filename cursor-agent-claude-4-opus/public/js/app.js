// Secure Notes App - Client Side JavaScript
(function() {
    'use strict';

    // State management
    const state = {
        user: null,
        accessToken: null,
        refreshToken: null,
        notes: [],
        currentPage: 1,
        totalPages: 1
    };

    // DOM elements
    const elements = {
        authContainer: document.getElementById('auth-container'),
        notesContainer: document.getElementById('notes-container'),
        loginForm: document.getElementById('login-form'),
        registerForm: document.getElementById('register-form'),
        createNoteForm: document.getElementById('create-note-form'),
        editNoteForm: document.getElementById('edit-note-form'),
        notesList: document.getElementById('notes-list'),
        userInfo: document.getElementById('user-info'),
        logoutBtn: document.getElementById('logout-btn'),
        searchInput: document.getElementById('search-input'),
        editModal: document.getElementById('edit-modal'),
        pagination: document.getElementById('pagination')
    };

    // API configuration
    const API_BASE = '/api';
    
    // Utility functions
    function escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function showError(elementId, message) {
        const errorElement = document.getElementById(elementId);
        if (errorElement) {
            errorElement.textContent = message;
            setTimeout(() => {
                errorElement.textContent = '';
            }, 5000);
        }
    }

    function formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    }

    // Token management
    function saveTokens(accessToken, refreshToken) {
        state.accessToken = accessToken;
        state.refreshToken = refreshToken;
        localStorage.setItem('accessToken', accessToken);
        localStorage.setItem('refreshToken', refreshToken);
    }

    function clearTokens() {
        state.accessToken = null;
        state.refreshToken = null;
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
    }

    function loadTokens() {
        state.accessToken = localStorage.getItem('accessToken');
        state.refreshToken = localStorage.getItem('refreshToken');
    }

    // API request wrapper with authentication
    async function apiRequest(endpoint, options = {}) {
        const config = {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...(state.accessToken && { 'Authorization': `Bearer ${state.accessToken}` }),
                ...options.headers
            }
        };

        if (options.body && typeof options.body === 'object') {
            config.body = JSON.stringify(options.body);
        }

        try {
            const response = await fetch(`${API_BASE}${endpoint}`, config);
            
            if (response.status === 401 && state.refreshToken) {
                // Try to refresh token
                const refreshResponse = await fetch(`${API_BASE}/auth/refresh`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ refreshToken: state.refreshToken })
                });

                if (refreshResponse.ok) {
                    const data = await refreshResponse.json();
                    saveTokens(data.accessToken, data.refreshToken);
                    
                    // Retry original request
                    config.headers.Authorization = `Bearer ${data.accessToken}`;
                    return fetch(`${API_BASE}${endpoint}`, config);
                } else {
                    // Refresh failed, logout
                    logout();
                    throw new Error('Session expired');
                }
            }

            return response;
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    }

    // Authentication functions
    async function register(username, email, password) {
        try {
            const response = await apiRequest('/auth/register', {
                method: 'POST',
                body: { username, email, password }
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Registration failed');
            }

            const data = await response.json();
            saveTokens(data.accessToken, data.refreshToken);
            state.user = data.user;
            showNotesApp();
        } catch (error) {
            showError('register-error', error.message);
        }
    }

    async function login(username, password) {
        try {
            const response = await apiRequest('/auth/login', {
                method: 'POST',
                body: { username, password }
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Login failed');
            }

            const data = await response.json();
            saveTokens(data.accessToken, data.refreshToken);
            state.user = data.user;
            showNotesApp();
        } catch (error) {
            showError('login-error', error.message);
        }
    }

    async function logout() {
        try {
            if (state.refreshToken) {
                await apiRequest('/auth/logout', {
                    method: 'POST',
                    body: { refreshToken: state.refreshToken }
                });
            }
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            clearTokens();
            state.user = null;
            state.notes = [];
            showAuthForm();
        }
    }

    async function getCurrentUser() {
        try {
            const response = await apiRequest('/auth/me');
            if (response.ok) {
                const data = await response.json();
                state.user = data.user;
                return true;
            }
        } catch (error) {
            console.error('Failed to get current user:', error);
        }
        return false;
    }

    // Notes functions
    async function loadNotes(page = 1) {
        try {
            const response = await apiRequest(`/notes?page=${page}&limit=12`);
            if (response.ok) {
                const data = await response.json();
                state.notes = data.notes;
                state.currentPage = data.pagination.page;
                state.totalPages = data.pagination.totalPages;
                renderNotes();
                renderPagination();
            }
        } catch (error) {
            console.error('Failed to load notes:', error);
        }
    }

    async function createNote(title, content) {
        try {
            const response = await apiRequest('/notes', {
                method: 'POST',
                body: { title, content }
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to create note');
            }

            await loadNotes(state.currentPage);
            elements.createNoteForm.reset();
        } catch (error) {
            alert(error.message);
        }
    }

    async function updateNote(id, title, content) {
        try {
            const response = await apiRequest(`/notes/${id}`, {
                method: 'PUT',
                body: { title, content }
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to update note');
            }

            await loadNotes(state.currentPage);
            closeEditModal();
        } catch (error) {
            alert(error.message);
        }
    }

    async function deleteNote(id) {
        if (!confirm('Are you sure you want to delete this note?')) {
            return;
        }

        try {
            const response = await apiRequest(`/notes/${id}`, {
                method: 'DELETE'
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to delete note');
            }

            await loadNotes(state.currentPage);
        } catch (error) {
            alert(error.message);
        }
    }

    async function searchNotes(query) {
        if (!query || query.trim().length < 2) {
            await loadNotes(1);
            return;
        }

        try {
            const response = await apiRequest(`/notes/search?q=${encodeURIComponent(query)}`);
            if (response.ok) {
                const data = await response.json();
                state.notes = data.notes;
                renderNotes();
                elements.pagination.innerHTML = ''; // Clear pagination for search results
            }
        } catch (error) {
            console.error('Search failed:', error);
        }
    }

    // UI functions
    function showAuthForm() {
        elements.authContainer.classList.remove('hidden');
        elements.notesContainer.classList.add('hidden');
    }

    function showNotesApp() {
        elements.authContainer.classList.add('hidden');
        elements.notesContainer.classList.remove('hidden');
        elements.userInfo.textContent = `Welcome, ${escapeHtml(state.user.username)}`;
        loadNotes();
    }

    function renderNotes() {
        if (state.notes.length === 0) {
            elements.notesList.innerHTML = '<p class="text-center">No notes found. Create your first note!</p>';
            return;
        }

        const notesHtml = state.notes.map(note => `
            <div class="note-card" data-note-id="${note.id}">
                <h3>${escapeHtml(note.title)}</h3>
                <p>${escapeHtml(note.content)}</p>
                <div class="note-meta">
                    Updated: ${formatDate(note.updated_at)}
                </div>
                <div class="note-actions">
                    <button class="btn btn-primary btn-sm edit-note" data-note-id="${note.id}">Edit</button>
                    <button class="btn btn-danger btn-sm delete-note" data-note-id="${note.id}">Delete</button>
                </div>
            </div>
        `).join('');

        elements.notesList.innerHTML = notesHtml;
    }

    function renderPagination() {
        if (state.totalPages <= 1) {
            elements.pagination.innerHTML = '';
            return;
        }

        let paginationHtml = '';
        
        // Previous button
        paginationHtml += `<button ${state.currentPage === 1 ? 'disabled' : ''} data-page="${state.currentPage - 1}">Previous</button>`;
        
        // Page numbers
        for (let i = 1; i <= state.totalPages; i++) {
            if (i === 1 || i === state.totalPages || (i >= state.currentPage - 2 && i <= state.currentPage + 2)) {
                paginationHtml += `<button class="${i === state.currentPage ? 'active' : ''}" data-page="${i}">${i}</button>`;
            } else if (i === state.currentPage - 3 || i === state.currentPage + 3) {
                paginationHtml += '<span>...</span>';
            }
        }
        
        // Next button
        paginationHtml += `<button ${state.currentPage === state.totalPages ? 'disabled' : ''} data-page="${state.currentPage + 1}">Next</button>`;
        
        elements.pagination.innerHTML = paginationHtml;
    }

    function openEditModal(noteId) {
        const note = state.notes.find(n => n.id === parseInt(noteId));
        if (!note) return;

        document.getElementById('edit-note-id').value = note.id;
        document.getElementById('edit-note-title').value = note.title;
        document.getElementById('edit-note-content').value = note.content;
        elements.editModal.classList.remove('hidden');
    }

    function closeEditModal() {
        elements.editModal.classList.add('hidden');
        elements.editNoteForm.reset();
    }

    // Event listeners
    document.querySelectorAll('.tab-button').forEach(button => {
        button.addEventListener('click', (e) => {
            const tab = e.target.dataset.tab;
            
            // Update tab buttons
            document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
            e.target.classList.add('active');
            
            // Update forms
            document.querySelectorAll('.auth-form-content').forEach(form => form.classList.remove('active'));
            document.getElementById(`${tab}-form`).classList.add('active');
        });
    });

    elements.loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = e.target.username.value;
        const password = e.target.password.value;
        await login(username, password);
    });

    elements.registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = e.target.username.value;
        const email = e.target.email.value;
        const password = e.target.password.value;
        await register(username, email, password);
    });

    elements.createNoteForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const title = document.getElementById('note-title').value;
        const content = document.getElementById('note-content').value;
        await createNote(title, content);
    });

    elements.editNoteForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const id = document.getElementById('edit-note-id').value;
        const title = document.getElementById('edit-note-title').value;
        const content = document.getElementById('edit-note-content').value;
        await updateNote(id, title, content);
    });

    elements.logoutBtn.addEventListener('click', logout);

    elements.searchInput.addEventListener('input', (e) => {
        const query = e.target.value;
        clearTimeout(window.searchTimeout);
        window.searchTimeout = setTimeout(() => {
            searchNotes(query);
        }, 300);
    });

    elements.notesList.addEventListener('click', (e) => {
        if (e.target.classList.contains('edit-note')) {
            openEditModal(e.target.dataset.noteId);
        } else if (e.target.classList.contains('delete-note')) {
            deleteNote(e.target.dataset.noteId);
        }
    });

    elements.pagination.addEventListener('click', (e) => {
        if (e.target.tagName === 'BUTTON' && !e.target.disabled) {
            const page = parseInt(e.target.dataset.page);
            loadNotes(page);
        }
    });

    document.querySelector('.close').addEventListener('click', closeEditModal);
    document.getElementById('cancel-edit').addEventListener('click', closeEditModal);

    elements.editModal.addEventListener('click', (e) => {
        if (e.target === elements.editModal) {
            closeEditModal();
        }
    });

    // Initialize app
    async function init() {
        loadTokens();
        if (state.accessToken) {
            const isAuthenticated = await getCurrentUser();
            if (isAuthenticated) {
                showNotesApp();
            } else {
                showAuthForm();
            }
        } else {
            showAuthForm();
        }
    }

    init();
})();