document.addEventListener('DOMContentLoaded', () => {
    // API Base URL (if your frontend is served from a different port during dev)
    const API_BASE_URL = ''; // Assuming same origin

    // UI Elements
    const messageArea = document.getElementById('messageArea');
    const registrationFormArea = document.getElementById('registrationFormArea');
    const loginFormArea = document.getElementById('loginFormArea');
    const noteManagementArea = document.getElementById('noteManagementArea');

    const registrationForm = document.getElementById('registrationForm');
    const loginForm = document.getElementById('loginForm');
    const createNoteForm = document.getElementById('createNoteForm');
    const updateNoteForm = document.getElementById('updateNoteForm');
    const updateNoteFormArea = document.getElementById('updateNoteFormArea');
    const cancelUpdateButton = document.getElementById('cancelUpdateButton');

    const notesList = document.getElementById('notesList');
    const logoutButton = document.getElementById('logoutButton');

    // State
    let jwtToken = localStorage.getItem('jwtToken');
    let csrfToken = null;

    // --- CSRF Token Management ---
    async function fetchCsrfToken() {
        try {
            const response = await fetch(`${API_BASE_URL}/api/auth/csrf-token`);
            if (!response.ok) {
                throw new Error(`Failed to fetch CSRF token: ${response.statusText}`);
            }
            const data = await response.json();
            csrfToken = data.csrfToken;
            console.log('CSRF Token fetched:', csrfToken);
        } catch (error) {
            displayMessage(`Error fetching CSRF token: ${error.message}`, 'error');
            console.error('fetchCsrfToken error:', error);
        }
    }

    // --- Helper Functions ---
    function displayMessage(message, type = 'info') { // type can be 'info', 'success', 'error'
        messageArea.textContent = message;
        messageArea.className = type; // Allows styling based on type
        setTimeout(() => { messageArea.textContent = ''; messageArea.className = ''; }, 5000);
    }

    async function fetchWithAuth(url, options = {}) {
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers,
        };

        if (jwtToken) {
            headers['Authorization'] = `Bearer ${jwtToken}`;
        }
        if (csrfToken && options.method !== 'GET' && options.method !== 'HEAD') {
            headers['X-CSRF-Token'] = csrfToken;
        }

        options.headers = headers;
        
        try {
            const response = await fetch(url, options);
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: response.statusText }));
                const errorMessages = errorData.errors ? errorData.errors.map(e => e.msg).join(', ') : errorData.message;
                throw new Error(`HTTP error! status: ${response.status} - ${errorMessages}`);
            }
            // For 204 No Content, response.json() will fail.
            if (response.status === 204) {
                return null; 
            }
            return await response.json();
        } catch (error) {
            console.error('fetchWithAuth error:', error);
            displayMessage(error.message, 'error');
            throw error; // Re-throw to be caught by calling function if needed
        }
    }

    function showView(view) {
        registrationFormArea.style.display = 'none';
        loginFormArea.style.display = 'none';
        noteManagementArea.style.display = 'none';
        updateNoteFormArea.style.display = 'none'; // Hide update form by default

        if (view === 'login') {
            loginFormArea.style.display = 'block';
            registrationFormArea.style.display = 'block'; // Show both for initial state
        } else if (view === 'notes') {
            noteManagementArea.style.display = 'block';
        }
    }

    // --- Authentication ---
    registrationForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('regUsername').value;
        const email = document.getElementById('regEmail').value;
        const password = document.getElementById('regPassword').value;

        try {
            const data = await fetchWithAuth(`${API_BASE_URL}/api/auth/register`, {
                method: 'POST',
                body: JSON.stringify({ username, email, password }),
            });
            displayMessage('Registration successful! Please login.', 'success');
            registrationForm.reset();
        } catch (error) {
            // Error already displayed by fetchWithAuth
        }
    });

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;

        try {
            const data = await fetchWithAuth(`${API_BASE_URL}/api/auth/login`, {
                method: 'POST',
                body: JSON.stringify({ email, password }),
            });
            jwtToken = data.token;
            localStorage.setItem('jwtToken', jwtToken);
            loginForm.reset();
            await fetchCsrfToken(); // Fetch CSRF token after login
            showView('notes');
            loadNotes();
            displayMessage('Login successful!', 'success');
        } catch (error) {
            // Error already displayed by fetchWithAuth
        }
    });

    logoutButton.addEventListener('click', () => {
        jwtToken = null;
        csrfToken = null;
        localStorage.removeItem('jwtToken');
        showView('login');
        notesList.innerHTML = ''; // Clear notes
        displayMessage('Logged out.', 'info');
    });

    // --- Note Management ---
    async function loadNotes() {
        if (!jwtToken) return;
        displayMessage('Loading notes...', 'info');
        try {
            const notes = await fetchWithAuth(`${API_BASE_URL}/api/notes`);
            notesList.innerHTML = ''; // Clear existing notes
            if (notes.length === 0) {
                notesList.innerHTML = '<p>No notes found. Create one!</p>';
            } else {
                notes.forEach(note => {
                    const noteEl = document.createElement('div');
                    noteEl.classList.add('note');
                    noteEl.innerHTML = `
                        <h4>${escapeHTML(note.title)}</h4>
                        <p>${escapeHTML(note.content)}</p>
                        <small>Last updated: ${new Date(note.updated_at).toLocaleString()}</small>
                        <div class="actions">
                            <button data-id="${note.id}" class="update">Update</button>
                            <button data-id="${note.id}" class="delete">Delete</button>
                        </div>
                    `;
                    notesList.appendChild(noteEl);
                });
            }
            displayMessage('', 'info'); // Clear loading message
        } catch (error) {
            // Error already displayed by fetchWithAuth
        }
    }

    createNoteForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const title = document.getElementById('noteTitle').value;
        const content = document.getElementById('noteContent').value;

        try {
            await fetchWithAuth(`${API_BASE_URL}/api/notes`, {
                method: 'POST',
                body: JSON.stringify({ title, content }),
            });
            createNoteForm.reset();
            loadNotes();
            displayMessage('Note created successfully!', 'success');
        } catch (error) {
            // Error already displayed by fetchWithAuth
        }
    });

    notesList.addEventListener('click', async (e) => {
        const target = e.target;
        const noteId = target.dataset.id;

        if (target.classList.contains('delete')) {
            if (!noteId) return;
            if (confirm('Are you sure you want to delete this note?')) {
                try {
                    await fetchWithAuth(`${API_BASE_URL}/api/notes/${noteId}`, {
                        method: 'DELETE',
                    });
                    loadNotes();
                    displayMessage('Note deleted successfully!', 'success');
                } catch (error) {
                    // Error already displayed by fetchWithAuth
                }
            }
        } else if (target.classList.contains('update')) {
            if (!noteId) return;
            // Fetch the note details to populate the update form
            try {
                const note = await fetchWithAuth(`${API_BASE_URL}/api/notes/${noteId}`);
                if (note) {
                    document.getElementById('updateNoteId').value = note.id;
                    document.getElementById('updateNoteTitle').value = note.title;
                    document.getElementById('updateNoteContent').value = note.content;
                    updateNoteFormArea.style.display = 'block';
                    noteManagementArea.style.display = 'none'; // Hide main notes view
                }
            } catch (error) {
                // Error handled by fetchWithAuth
            }
        }
    });
    
    updateNoteForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const id = document.getElementById('updateNoteId').value;
        const title = document.getElementById('updateNoteTitle').value;
        const content = document.getElementById('updateNoteContent').value;

        try {
            await fetchWithAuth(`${API_BASE_URL}/api/notes/${id}`, {
                method: 'PUT',
                body: JSON.stringify({ title, content }),
            });
            updateNoteForm.reset();
            updateNoteFormArea.style.display = 'none';
            showView('notes'); // Go back to notes view
            loadNotes();
            displayMessage('Note updated successfully!', 'success');
        } catch (error) {
            // Error already displayed by fetchWithAuth
        }
    });

    cancelUpdateButton.addEventListener('click', () => {
        updateNoteForm.reset();
        updateNoteFormArea.style.display = 'none';
        showView('notes'); // Go back to notes view
    });

    // --- Initialization ---
    async function init() {
        if (jwtToken) {
            // Potentially validate token here by making a protected request
            // For now, assume if token exists, it's valid.
            await fetchCsrfToken(); // Fetch CSRF token if logged in
            showView('notes');
            loadNotes();
        } else {
            await fetchCsrfToken(); // Fetch CSRF token for login/register forms too
            showView('login');
        }
    }
    
    function escapeHTML(str) {
        const div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    init();
});
