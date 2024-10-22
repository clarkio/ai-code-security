const API_URL = 'http://localhost:5000/api';

// Check if token exists on page load
document.addEventListener('DOMContentLoaded', () => {
  const token = localStorage.getItem('token');
  if (token) {
    document.getElementById('auth-forms').style.display = 'none';
    document.getElementById('notes-section').style.display = 'block';
    fetchNotes();
  }
});

// Register User
async function register() {
  const username = document.getElementById('register-username').value;
  const password = document.getElementById('register-password').value;

  const response = await fetch(`${API_URL}/auth/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ username, password })
  });

  const data = await response.json();
  if (data.token) {
    localStorage.setItem('token', data.token);
    document.getElementById('auth-forms').style.display = 'none';
    document.getElementById('notes-section').style.display = 'block';
    fetchNotes();
  } else {
    alert('Registration failed: ' + data.errors[0].msg);
  }
}

// Login User
async function login() {
  const username = document.getElementById('login-username').value;
  const password = document.getElementById('login-password').value;

  const response = await fetch(`${API_URL}/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ username, password })
  });

  const data = await response.json();
  if (data.token) {
    localStorage.setItem('token', data.token);
    document.getElementById('auth-forms').style.display = 'none';
    document.getElementById('notes-section').style.display = 'block';
    fetchNotes();
  } else {
    alert('Login failed: ' + data.msg);
  }
}

// Logout
function logout() {
  localStorage.removeItem('token');
  document.getElementById('notes-section').style.display = 'none';
  document.getElementById('auth-forms').style.display = 'block';
}

// Fetch Notes
async function fetchNotes() {
  const token = localStorage.getItem('token');
  const response = await fetch(`${API_URL}/notes`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });

  const notes = await response.json();
  const notesList = document.getElementById('notes-list');
  notesList.innerHTML = '';

  notes.forEach(note => {
    const li = document.createElement('li');
    li.innerHTML = `
      <h3>${note.title}</h3>
      <p>${note.body}</p>
      <button onclick="deleteNote('${note._id}')">Delete</button>
    `;
    notesList.appendChild(li);
  });
}

// Create Note
async function createNote() {
  const token = localStorage.getItem('token');
  const title = document.getElementById('note-title').value;
  const body = document.getElementById('note-body').value;

  const response = await fetch(`${API_URL}/notes`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ title, body })
  });

  const note = await response.json();
  fetchNotes(); // Refresh notes list
}

// Delete Note
async function deleteNote(id) {
  const token = localStorage.getItem('token');

  await fetch(`${API_URL}/notes/${id}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });

  fetchNotes(); // Refresh notes list
}
