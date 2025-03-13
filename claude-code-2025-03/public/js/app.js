// Global variables
let csrfToken = '';
let currentNote = null;

// DOM selectors
const authContainer = document.getElementById('auth-container');
const notesContainer = document.getElementById('notes-container');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const loginTab = document.getElementById('login-tab');
const registerTab = document.getElementById('register-tab');
const usernameDisplay = document.getElementById('username');
const logoutBtn = document.getElementById('logout-btn');
const loginError = document.getElementById('login-error');
const registerError = document.getElementById('register-error');
const notesList = document.getElementById('notes-list');
const noteEditor = document.getElementById('note-editor');
const noteIdInput = document.getElementById('note-id');
const noteTitleInput = document.getElementById('note-title');
const noteContentInput = document.getElementById('note-content');
const newNoteBtn = document.getElementById('new-note-btn');
const saveNoteBtn = document.getElementById('save-note-btn');
const cancelNoteBtn = document.getElementById('cancel-note-btn');
const deleteNoteBtn = document.getElementById('delete-note-btn');
const noteError = document.getElementById('note-error');

// Event listeners for tabs
loginTab.addEventListener('click', () => {
  loginTab.classList.add('active');
  registerTab.classList.remove('active');
  loginForm.style.display = 'block';
  registerForm.style.display = 'none';
  loginError.textContent = '';
});

registerTab.addEventListener('click', () => {
  registerTab.classList.add('active');
  loginTab.classList.remove('active');
  registerForm.style.display = 'block';
  loginForm.style.display = 'none';
  registerError.textContent = '';
});

// Event listener for login form
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  loginError.textContent = '';
  
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  
  if (!username || !password) {
    loginError.textContent = 'Both username and password are required';
    return;
  }
  
  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password }),
      credentials: 'same-origin',
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      loginError.textContent = data.error ? data.error.message : 'Login failed';
      return;
    }
    
    // Login successful, get CSRF token and fetch notes
    await fetchCsrfToken();
    await checkAuthStatus();
  } catch (error) {
    console.error('Login error:', error);
    loginError.textContent = 'An error occurred during login. Please try again.';
  }
});

// Event listener for register form
registerForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  registerError.textContent = '';
  
  const username = document.getElementById('register-username').value.trim();
  const email = document.getElementById('register-email').value.trim();
  const password = document.getElementById('register-password').value;
  const confirmPassword = document.getElementById('register-confirm-password').value;
  
  if (password !== confirmPassword) {
    registerError.textContent = 'Passwords do not match';
    return;
  }
  
  try {
    const response = await fetch('/api/auth/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, email, password, confirmPassword }),
      credentials: 'same-origin',
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      if (data.errors && data.errors.length > 0) {
        registerError.textContent = data.errors.map(err => err.message).join(', ');
      } else if (data.error) {
        registerError.textContent = data.error.message;
      } else {
        registerError.textContent = 'Registration failed';
      }
      return;
    }
    
    // Registration successful, switch to login tab
    loginTab.click();
    document.getElementById('login-username').value = username;
    loginError.textContent = 'Registration successful! You can now log in.';
    loginError.style.color = 'green';
  } catch (error) {
    console.error('Registration error:', error);
    registerError.textContent = 'An error occurred during registration. Please try again.';
  }
});

// Event listener for logout button
logoutBtn.addEventListener('click', async () => {
  try {
    await fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'same-origin',
    });
    
    // Reset UI state
    showAuthContainer();
  } catch (error) {
    console.error('Logout error:', error);
    alert('Failed to log out. Please try again.');
  }
});

// Event listener for new note button
newNoteBtn.addEventListener('click', () => {
  resetNoteEditor();
  noteEditor.style.display = 'block';
  deleteNoteBtn.style.display = 'none';
});

// Event listener for cancel note button
cancelNoteBtn.addEventListener('click', () => {
  noteEditor.style.display = 'none';
  resetNoteEditor();
});

// Event listener for save note button
saveNoteBtn.addEventListener('click', async () => {
  noteError.textContent = '';
  
  const title = noteTitleInput.value.trim();
  const content = noteContentInput.value.trim();
  
  if (!title || !content) {
    noteError.textContent = 'Title and content are required';
    return;
  }
  
  try {
    let url = '/api/notes';
    let method = 'POST';
    
    // If editing existing note
    if (noteIdInput.value) {
      url = `/api/notes/${noteIdInput.value}`;
      method = 'PUT';
    }
    
    const response = await fetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'CSRF-Token': csrfToken,
      },
      body: JSON.stringify({ title, content }),
      credentials: 'same-origin',
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      noteError.textContent = data.error ? data.error.message : 'Failed to save note';
      return;
    }
    
    // Refresh notes and hide editor
    await fetchNotes();
    noteEditor.style.display = 'none';
    resetNoteEditor();
  } catch (error) {
    console.error('Save note error:', error);
    noteError.textContent = 'An error occurred while saving the note';
  }
});

// Event listener for delete note button
deleteNoteBtn.addEventListener('click', async () => {
  if (!noteIdInput.value) return;
  
  if (!confirm('Are you sure you want to delete this note?')) {
    return;
  }
  
  try {
    const response = await fetch(`/api/notes/${noteIdInput.value}`, {
      method: 'DELETE',
      headers: {
        'CSRF-Token': csrfToken,
      },
      credentials: 'same-origin',
    });
    
    if (!response.ok) {
      const data = await response.json();
      noteError.textContent = data.error ? data.error.message : 'Failed to delete note';
      return;
    }
    
    // Refresh notes and hide editor
    await fetchNotes();
    noteEditor.style.display = 'none';
    resetNoteEditor();
  } catch (error) {
    console.error('Delete note error:', error);
    noteError.textContent = 'An error occurred while deleting the note';
  }
});

// Fetch CSRF token
async function fetchCsrfToken() {
  try {
    const response = await fetch('/api/csrf/token', {
      credentials: 'same-origin',
    });
    
    if (!response.ok) {
      console.error('Failed to fetch CSRF token');
      return;
    }
    
    const data = await response.json();
    csrfToken = data.csrfToken;
  } catch (error) {
    console.error('CSRF token fetch error:', error);
  }
}

// Check authentication status
async function checkAuthStatus() {
  try {
    const response = await fetch('/api/auth/me', {
      credentials: 'same-origin',
    });
    
    if (!response.ok) {
      showAuthContainer();
      return;
    }
    
    const data = await response.json();
    
    // User is authenticated
    usernameDisplay.textContent = data.user.username;
    await fetchCsrfToken();
    await fetchNotes();
    showNotesContainer();
  } catch (error) {
    console.error('Auth status check error:', error);
    showAuthContainer();
  }
}

// Fetch all notes
async function fetchNotes() {
  try {
    const response = await fetch('/api/notes', {
      credentials: 'same-origin',
    });
    
    if (!response.ok) {
      console.error('Failed to fetch notes');
      return;
    }
    
    const data = await response.json();
    renderNotes(data.notes);
  } catch (error) {
    console.error('Fetch notes error:', error);
  }
}

// Render notes list
function renderNotes(notes) {
  notesList.innerHTML = '';
  
  if (notes.length === 0) {
    notesList.innerHTML = '<div class="note-item"><p>No notes yet. Create your first note!</p></div>';
    return;
  }
  
  notes.forEach(note => {
    const noteItem = document.createElement('div');
    noteItem.className = 'note-item';
    noteItem.dataset.id = note.id;
    
    const title = document.createElement('h3');
    title.textContent = note.title;
    
    const preview = document.createElement('p');
    preview.textContent = note.content.length > 100 
      ? note.content.substring(0, 100) + '...' 
      : note.content;
    
    const date = document.createElement('div');
    date.className = 'date';
    date.textContent = new Date(note.updatedAt).toLocaleString();
    
    noteItem.appendChild(title);
    noteItem.appendChild(preview);
    noteItem.appendChild(date);
    
    noteItem.addEventListener('click', () => loadNote(note));
    
    notesList.appendChild(noteItem);
  });
}

// Load note into editor
function loadNote(note) {
  currentNote = note;
  noteIdInput.value = note.id;
  noteTitleInput.value = note.title;
  noteContentInput.value = note.content;
  noteEditor.style.display = 'block';
  deleteNoteBtn.style.display = 'inline-block';
  noteError.textContent = '';
}

// Reset note editor
function resetNoteEditor() {
  currentNote = null;
  noteIdInput.value = '';
  noteTitleInput.value = '';
  noteContentInput.value = '';
  noteError.textContent = '';
}

// Show auth container
function showAuthContainer() {
  authContainer.style.display = 'block';
  notesContainer.style.display = 'none';
  usernameDisplay.textContent = '';
  logoutBtn.style.display = 'none';
  resetNoteEditor();
}

// Show notes container
function showNotesContainer() {
  authContainer.style.display = 'none';
  notesContainer.style.display = 'grid';
  logoutBtn.style.display = 'inline-block';
  noteEditor.style.display = 'none';
}

// Initialize app
function init() {
  // Check if user is authenticated
  checkAuthStatus();
  
  // Clear form inputs for security
  document.getElementById('login-username').value = '';
  document.getElementById('login-password').value = '';
  document.getElementById('register-username').value = '';
  document.getElementById('register-email').value = '';
  document.getElementById('register-password').value = '';
  document.getElementById('register-confirm-password').value = '';
}

// Start the app
init();