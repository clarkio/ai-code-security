const notesContainer = document.getElementById('notesContainer');
const noteForm = document.getElementById('noteForm');

const loginForm = document.getElementById('loginForm');

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });

    if (response.ok) {
        const data = await response.json();
        localStorage.setItem('token', data.token); // Store the token
        fetchNotes(); // Fetch notes after successful login
    } else {
        alert('Login failed');
    }
});

const registerForm = document.getElementById('registerForm');

registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('registerUsername').value;
    const password = document.getElementById('registerPassword').value;

    const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });

    if (response.ok) {
        alert('User registered successfully');
    } else {
        alert('Registration failed');
    }
});

// Fetch notes
async function fetchNotes() {
    const response = await fetch('/api/notes', {
        method: 'GET',
        headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
    });
    const notes = await response.json();
    notesContainer.innerHTML = notes.map(note => `
        <div>
            <h3>${note.title}</h3>
            <p>${note.content}</p>
            <button onclick="deleteNote('${note._id}')">Delete</button>
        </div>
    `).join('');
}

// Add note
noteForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const title = document.getElementById('title').value;
    const content = document.getElementById('content').value;

    await fetch('/api/notes', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + localStorage.getItem('token')
        },
        body: JSON.stringify({ title, content })
    });

    noteForm.reset();
    fetchNotes();
});

// Delete note
async function deleteNote(id) {
    await fetch(`/api/notes/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
    });
    fetchNotes();
}

// Initial fetch
fetchNotes();