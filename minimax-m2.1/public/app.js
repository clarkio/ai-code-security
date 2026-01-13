(function() {
  'use strict';

  const API_URL = '/api';
  let accessToken = localStorage.getItem('accessToken');
  let refreshToken = localStorage.getItem('refreshToken');
  let editingNoteId = null;

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  function showError(message) {
    const errorEl = document.getElementById('auth-error');
    errorEl.textContent = message;
    errorEl.classList.remove('hidden');
  }

  function hideError() {
    const errorEl = document.getElementById('auth-error');
    errorEl.classList.add('hidden');
  }

  async function request(url, options = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (accessToken) headers['Authorization'] = `Bearer ${accessToken}`;

    const response = await fetch(`${API_URL}${url}`, {
      ...options,
      headers: { ...headers, ...options.headers }
    });

    const data = await response.json();

    if (response.status === 401 && refreshToken && !options._retry) {
      options._retry = true;
      const refreshed = await refreshAccessToken();
      if (refreshed) {
        return request(url, options);
      }
    }

    if (!response.ok) {
      throw new Error(data.error || 'Request failed');
    }

    return data;
  }

  async function refreshAccessToken() {
    try {
      const res = await fetch(`${API_URL}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken })
      });

      if (!res.ok) return false;

      const data = await res.json();
      accessToken = data.accessToken;
      refreshToken = data.refreshToken;
      localStorage.setItem('accessToken', accessToken);
      localStorage.setItem('refreshToken', refreshToken);
      return true;
    } catch {
      return false;
    }
  }

  function showAuth(show) {
    document.getElementById('auth-section').classList.toggle('hidden', !show);
    document.getElementById('notes-section').classList.toggle('hidden', show);
    document.getElementById('nav').classList.toggle('hidden', !show);
  }

  async function login(username, password) {
    const data = await request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });

    accessToken = data.accessToken;
    refreshToken = data.refreshToken;
    localStorage.setItem('accessToken', accessToken);
    localStorage.setItem('refreshToken', refreshToken);

    document.getElementById('user-display').textContent = data.user.username;
    showAuth(false);
    loadNotes();
  }

  async function register(username, email, password) {
    await request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, email, password })
    });

    document.getElementById('login-tab').click();
    alert('Registration successful! Please login.');
  }

  async function logout() {
    try {
      await request('/auth/logout', {
        method: 'POST',
        body: JSON.stringify({ refreshToken })
      });
    } catch {}

    accessToken = null;
    refreshToken = null;
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    showAuth(true);
  }

  async function loadNotes() {
    const data = await request('/notes');
    renderNotes(data.notes);
  }

  function renderNotes(notes) {
    const container = document.getElementById('notes-list');
    container.innerHTML = notes.map(note => `
      <div class="note-card" data-id="${note.id}">
        <h3>${escapeHtml(note.title)}</h3>
        <p class="date">Updated: ${new Date(note.updated_at).toLocaleDateString()}</p>
        <div class="actions">
          <button class="btn btn-secondary edit-btn" data-id="${note.id}">Edit</button>
          <button class="btn btn-danger delete-btn" data-id="${note.id}">Delete</button>
        </div>
      </div>
    `).join('');
  }

  async function saveNote(title, content) {
    const body = { title, content };

    if (editingNoteId) {
      await request(`/notes/${editingNoteId}`, {
        method: 'PUT',
        body: JSON.stringify(body)
      });
    } else {
      await request('/notes', {
        method: 'POST',
        body: JSON.stringify(body)
      });
    }

    editingNoteId = null;
    hideEditor();
    loadNotes();
  }

  async function deleteNote(id) {
    if (!confirm('Delete this note?')) return;
    await request(`/notes/${id}`, { method: 'DELETE' });
    loadNotes();
  }

  function showEditor(note = null) {
    const editor = document.getElementById('note-editor');
    const titleInput = document.getElementById('note-title');
    const contentInput = document.getElementById('note-content');

    if (note) {
      editingNoteId = note.id;
      titleInput.value = note.title;
      contentInput.value = note.content || '';
    } else {
      editingNoteId = null;
      titleInput.value = '';
      contentInput.value = '';
    }

    editor.classList.remove('hidden');
    titleInput.focus();
  }

  function hideEditor() {
    document.getElementById('note-editor').classList.add('hidden');
  }

  document.getElementById('login-tab').addEventListener('click', function() {
    this.classList.add('active');
    document.getElementById('register-tab').classList.remove('active');
    document.getElementById('login-form').classList.remove('hidden');
    document.getElementById('register-form').classList.add('hidden');
    hideError();
  });

  document.getElementById('register-tab').addEventListener('click', function() {
    this.classList.add('active');
    document.getElementById('login-tab').classList.remove('active');
    document.getElementById('register-form').classList.remove('hidden');
    document.getElementById('login-form').classList.add('hidden');
    hideError();
  });

  document.getElementById('login-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    hideError();
    const username = this.username.value.trim();
    const password = this.password.value;

    try {
      await login(username, password);
      this.reset();
    } catch (err) {
      showError(err.message);
    }
  });

  document.getElementById('register-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    hideError();

    const username = this.username.value.trim();
    const email = this.email.value.trim();
    const password = this.password.value;
    const confirm = this.confirmPassword.value;

    if (password !== confirm) {
      showError('Passwords do not match');
      return;
    }

    try {
      await register(username, email, password);
      this.reset();
    } catch (err) {
      showError(err.message);
    }
  });

  document.getElementById('logout-btn').addEventListener('click', logout);

  document.getElementById('new-note-btn').addEventListener('click', () => showEditor());

  document.getElementById('save-note-btn').addEventListener('click', async () => {
    const title = document.getElementById('note-title').value.trim();
    const content = document.getElementById('note-content').value.trim();

    if (!title) {
      showError('Title is required');
      return;
    }

    try {
      await saveNote(title, content);
    } catch (err) {
      showError(err.message);
    }
  });

  document.getElementById('cancel-note-btn').addEventListener('click', () => {
    hideEditor();
    editingNoteId = null;
  });

  document.getElementById('notes-list').addEventListener('click', async function(e) {
    const editBtn = e.target.closest('.edit-btn');
    const deleteBtn = e.target.closest('.delete-btn');
    const card = e.target.closest('.note-card');

    if (deleteBtn) {
      await deleteNote(deleteBtn.dataset.id);
    } else if (editBtn) {
      const id = editBtn.dataset.id;
      const notes = await request('/notes');
      const note = notes.notes.find(n => n.id === id);
      if (note) showEditor(note);
    } else if (card) {
      const id = card.dataset.id;
      const notes = await request('/notes');
      const note = notes.notes.find(n => n.id === id);
      if (note) showEditor(note);
    }
  });

  if (accessToken && refreshToken) {
    showAuth(false);
    loadNotes().catch(() => {
      accessToken = null;
      refreshToken = null;
      localStorage.removeItem('accessToken');
      localStorage.removeItem('refreshToken');
      showAuth(true);
    });
  } else {
    showAuth(true);
  }
})();
