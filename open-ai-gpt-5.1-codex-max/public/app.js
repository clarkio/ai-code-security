/* global document, fetch */
let csrfToken = '';
let currentUser = null;

const statusEl = document.getElementById('status');
const notesList = document.getElementById('notes');
const authForms = document.getElementById('auth-forms');
const notesPanel = document.getElementById('notes-panel');
const usernameLabel = document.getElementById('username-label');

const setStatus = (message, type = 'error') => {
  if (!message) {
    statusEl.classList.add('hidden');
    statusEl.textContent = '';
    statusEl.classList.remove('error', 'success');
    return;
  }
  statusEl.textContent = message;
  statusEl.classList.remove('hidden');
  statusEl.classList.remove('error', 'success');
  statusEl.classList.add(type);
};

const refreshCsrf = async () => {
  const res = await fetch('/csrf-token', { credentials: 'include' });
  if (res.ok) {
    const data = await res.json();
    csrfToken = data.csrfToken;
  }
};

const fetchWithCsrf = async (url, options = {}) => {
  const opts = { credentials: 'include', headers: {}, ...options };
  opts.headers['Content-Type'] = 'application/json';
  if (csrfToken) {
    opts.headers['x-csrf-token'] = csrfToken;
  }
  return fetch(url, opts);
};

const renderNotes = (notes) => {
  notesList.innerHTML = '';
  if (!notes.length) {
    const empty = document.createElement('div');
    empty.className = 'muted';
    empty.textContent = 'No notes yet.';
    notesList.appendChild(empty);
    return;
  }
  notes.forEach((note) => {
    const card = document.createElement('div');
    card.className = 'note-card';
    const title = document.createElement('h3');
    title.textContent = note.title;
    const content = document.createElement('p');
    content.textContent = note.content;
    const actions = document.createElement('div');
    actions.className = 'note-actions';
    const editBtn = document.createElement('button');
    editBtn.className = 'button-secondary';
    editBtn.textContent = 'Edit';
    editBtn.onclick = async () => {
      const newTitle = prompt('Update title', note.title);
      const newContent = prompt('Update content', note.content);
      if (newTitle && newContent) {
        await refreshCsrf();
        const res = await fetchWithCsrf(`/notes/${note.id}`, {
          method: 'PUT',
          body: JSON.stringify({ title: newTitle, content: newContent }),
        });
        if (!res.ok) {
          setStatus('Could not update note', 'error');
        } else {
          setStatus('Note updated', 'success');
          loadNotes();
        }
      }
    };
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'button-secondary';
    deleteBtn.textContent = 'Delete';
    deleteBtn.onclick = async () => {
      if (!confirm('Delete note?')) return;
      await refreshCsrf();
      const res = await fetchWithCsrf(`/notes/${note.id}`, { method: 'DELETE' });
      if (!res.ok) {
        setStatus('Could not delete note', 'error');
      } else {
        setStatus('Note deleted', 'success');
        loadNotes();
      }
    };
    actions.append(editBtn, deleteBtn);
    card.append(title, content, actions);
    notesList.appendChild(card);
  });
};

const loadNotes = async () => {
  const res = await fetch('/notes', { credentials: 'include' });
  if (res.status === 401) {
    renderNotes([]);
    return;
  }
  const data = await res.json();
  renderNotes(data.notes || []);
};

const checkSession = async () => {
  const res = await fetch('/auth/me', { credentials: 'include' });
  if (res.ok) {
    currentUser = await res.json();
    authForms.classList.add('hidden');
    notesPanel.classList.remove('hidden');
    usernameLabel.textContent = currentUser.username;
    loadNotes();
  } else {
    currentUser = null;
    authForms.classList.remove('hidden');
    notesPanel.classList.add('hidden');
    usernameLabel.textContent = '';
    renderNotes([]);
  }
};

document.getElementById('register-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  setStatus('');
  await refreshCsrf();
  const username = document.getElementById('register-username').value.trim();
  const password = document.getElementById('register-password').value;
  const res = await fetchWithCsrf('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) {
    const error = (await res.json()).error || 'Could not register';
    setStatus(error, 'error');
    return;
  }
  setStatus('Registered and signed in.', 'success');
  await refreshCsrf();
  await checkSession();
});

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  setStatus('');
  await refreshCsrf();
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const res = await fetchWithCsrf('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) {
    setStatus('Invalid credentials', 'error');
    return;
  }
  setStatus('Signed in.', 'success');
  await refreshCsrf();
  await checkSession();
});

document.getElementById('logout-btn').addEventListener('click', async () => {
  await refreshCsrf();
  const res = await fetchWithCsrf('/auth/logout', { method: 'POST' });
  if (res.ok) {
    setStatus('Signed out', 'success');
  }
  await refreshCsrf();
  await checkSession();
});

document.getElementById('note-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  await refreshCsrf();
  const title = document.getElementById('note-title').value.trim();
  const content = document.getElementById('note-content').value.trim();
  const res = await fetchWithCsrf('/notes', {
    method: 'POST',
    body: JSON.stringify({ title, content }),
  });
  if (!res.ok) {
    setStatus('Unable to create note', 'error');
    return;
  }
  document.getElementById('note-form').reset();
  setStatus('Note created', 'success');
  loadNotes();
});

(async () => {
  await refreshCsrf();
  await checkSession();
})();
