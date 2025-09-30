// API Base URL
const API_URL = "/api";

// State Management
let currentUser = null;
let notes = [];
let currentNoteId = null;

// DOM Elements
const authContainer = document.getElementById("auth-container");
const notesContainer = document.getElementById("notes-container");
const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");
const noteForm = document.getElementById("noteForm");
const showRegisterLink = document.getElementById("show-register");
const showLoginLink = document.getElementById("show-login");
const logoutBtn = document.getElementById("logout-btn");
const newNoteBtn = document.getElementById("new-note-btn");
const deleteNoteBtn = document.getElementById("delete-note-btn");
const cancelNoteBtn = document.getElementById("cancel-note-btn");

// Utility Functions
function showError(message) {
  const errorEl = document.getElementById("error-message");
  errorEl.textContent = message;
  errorEl.style.display = "block";
  setTimeout(() => {
    errorEl.style.display = "none";
  }, 5000);
}

function showSuccess(message) {
  const successEl = document.getElementById("success-message");
  successEl.textContent = message;
  successEl.style.display = "block";
  setTimeout(() => {
    successEl.style.display = "none";
  }, 3000);
}

function sanitizeHTML(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// API Functions
async function apiCall(endpoint, method = "GET", body = null) {
  try {
    const options = {
      method,
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include", // Important for cookies
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(`${API_URL}${endpoint}`, options);
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.message || "An error occurred");
    }

    return data;
  } catch (error) {
    throw error;
  }
}

// Auth Functions
async function login(username, password) {
  try {
    const data = await apiCall("/auth/login", "POST", { username, password });
    currentUser = data.user;
    showDashboard();
    await loadNotes();
    showSuccess("Logged in successfully!");
  } catch (error) {
    showError(error.message);
  }
}

async function register(username, password, confirmPassword) {
  try {
    const data = await apiCall("/auth/register", "POST", {
      username,
      password,
      confirmPassword,
    });
    currentUser = data.user;
    showDashboard();
    showSuccess("Registered successfully!");
  } catch (error) {
    showError(error.message);
  }
}

async function logout() {
  try {
    await apiCall("/auth/logout", "POST");
    currentUser = null;
    notes = [];
    showAuth();
    showSuccess("Logged out successfully!");
  } catch (error) {
    showError(error.message);
  }
}

// Notes Functions
async function loadNotes() {
  try {
    const data = await apiCall("/notes");
    notes = data.data;
    renderNotes();
  } catch (error) {
    showError("Failed to load notes");
  }
}

async function createNote(title, content) {
  try {
    const data = await apiCall("/notes", "POST", { title, content });
    notes.push(data.data);
    renderNotes();
    selectNote(data.data.id);
    showSuccess("Note created successfully!");
  } catch (error) {
    showError(error.message);
  }
}

async function updateNote(id, title, content) {
  try {
    const data = await apiCall(`/notes/${id}`, "PUT", { title, content });
    const index = notes.findIndex((n) => n.id === id);
    if (index !== -1) {
      notes[index] = data.data;
      renderNotes();
      selectNote(id);
    }
    showSuccess("Note updated successfully!");
  } catch (error) {
    showError(error.message);
  }
}

async function deleteNote(id) {
  if (!confirm("Are you sure you want to delete this note?")) {
    return;
  }

  try {
    await apiCall(`/notes/${id}`, "DELETE");
    notes = notes.filter((n) => n.id !== id);
    renderNotes();
    clearEditor();
    showSuccess("Note deleted successfully!");
  } catch (error) {
    showError(error.message);
  }
}

// UI Functions
function showAuth() {
  authContainer.style.display = "block";
  notesContainer.style.display = "none";
}

function showDashboard() {
  authContainer.style.display = "none";
  notesContainer.style.display = "block";
  document.getElementById("user-info").textContent = `Welcome, ${sanitizeHTML(
    currentUser.username
  )}`;
}

function renderNotes() {
  const notesItems = document.getElementById("notes-items");

  if (notes.length === 0) {
    notesItems.textContent = "";
    const emptyMsg = document.createElement("p");
    emptyMsg.style.textAlign = "center";
    emptyMsg.style.color = "#999";
    emptyMsg.style.marginTop = "20px";
    emptyMsg.textContent = "No notes yet";
    notesItems.appendChild(emptyMsg);
    return;
  }

  // Clear existing content
  notesItems.textContent = "";

  // Create note items using DOM methods (safer than innerHTML)
  notes.forEach((note) => {
    const noteItem = document.createElement("div");
    noteItem.className = "note-item";
    if (note.id === currentNoteId) {
      noteItem.classList.add("active");
    }
    noteItem.dataset.noteId = note.id;

    const title = document.createElement("h3");
    title.textContent = note.title;

    const date = document.createElement("p");
    date.textContent = new Date(note.updatedAt).toLocaleDateString();

    noteItem.appendChild(title);
    noteItem.appendChild(date);

    noteItem.addEventListener("click", () => {
      selectNote(note.id);
    });

    notesItems.appendChild(noteItem);
  });
}

function selectNote(noteId) {
  const note = notes.find((n) => n.id === noteId);
  if (!note) return;

  currentNoteId = noteId;

  document.getElementById("empty-state").style.display = "none";
  document.getElementById("editor-form").style.display = "block";

  document.getElementById("note-id").value = note.id;
  document.getElementById("note-title").value = note.title;
  document.getElementById("note-content").value = note.content;

  renderNotes();
}

function clearEditor() {
  currentNoteId = null;
  document.getElementById("empty-state").style.display = "flex";
  document.getElementById("editor-form").style.display = "none";
  document.getElementById("note-id").value = "";
  document.getElementById("note-title").value = "";
  document.getElementById("note-content").value = "";
  renderNotes();
}

// Event Listeners
showRegisterLink.addEventListener("click", (e) => {
  e.preventDefault();
  document.getElementById("login-form").style.display = "none";
  document.getElementById("register-form").style.display = "block";
});

showLoginLink.addEventListener("click", (e) => {
  e.preventDefault();
  document.getElementById("register-form").style.display = "none";
  document.getElementById("login-form").style.display = "block";
});

loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("login-username").value;
  const password = document.getElementById("login-password").value;
  await login(username, password);
});

registerForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("register-username").value;
  const password = document.getElementById("register-password").value;
  const confirmPassword = document.getElementById("register-confirm").value;

  if (password !== confirmPassword) {
    showError("Passwords do not match");
    return;
  }

  await register(username, password, confirmPassword);
});

logoutBtn.addEventListener("click", logout);

newNoteBtn.addEventListener("click", () => {
  clearEditor();
  document.getElementById("empty-state").style.display = "none";
  document.getElementById("editor-form").style.display = "block";
});

cancelNoteBtn.addEventListener("click", clearEditor);

noteForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const noteId = document.getElementById("note-id").value;
  const title = document.getElementById("note-title").value;
  const content = document.getElementById("note-content").value;

  if (noteId) {
    await updateNote(noteId, title, content);
  } else {
    await createNote(title, content);
  }
});

deleteNoteBtn.addEventListener("click", () => {
  const noteId = document.getElementById("note-id").value;
  if (noteId) {
    deleteNote(noteId);
  }
});

// Initialize
showAuth();
