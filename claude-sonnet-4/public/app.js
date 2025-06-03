// Security and API Configuration
const API_BASE = ''
let csrfToken = null
let authToken = localStorage.getItem('authToken')

// DOM Elements
const elements = {
  loading: document.getElementById('loading'),
  authContainer: document.getElementById('auth-container'),
  mainApp: document.getElementById('main-app'),
  loginForm: document.getElementById('login-form'),
  registerForm: document.getElementById('register-form'),
  noteModal: document.getElementById('note-modal'),
  deleteModal: document.getElementById('delete-modal'),
  notesList: document.getElementById('notes-list'),
  usernameDisplay: document.getElementById('username-display'),
  searchInput: document.getElementById('search-input'),
  newNoteBtn: document.getElementById('new-note-btn'),
  logoutBtn: document.getElementById('logout-btn'),
  noteForm: document.getElementById('note-form'),
  modalTitle: document.getElementById('modal-title'),
  confirmDeleteBtn: document.getElementById('confirm-delete-btn')
}

// Application State
let currentUser = null
let notes = []
let currentNoteId = null
let filteredNotes = []

// Security: XSS Prevention
function sanitizeHtml (text) {
  const div = document.createElement('div')
  div.textContent = text
  return div.innerHTML
}

// Security: Input validation
function validateInput (input, type) {
  switch (type) {
    case 'username':
      return /^[a-zA-Z0-9_]{3,30}$/.test(input)
    case 'email':
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input)
    case 'password':
      return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(
        input
      )
    default:
      return true
  }
}

// API Helper with CSRF protection
async function apiRequest (endpoint, options = {}) {
  const config = {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers
    },
    ...options
  }

  // Add CSRF token for non-GET requests
  if (options.method && options.method !== 'GET' && csrfToken) {
    config.headers['X-CSRF-Token'] = csrfToken
  }

  // Add auth token if available
  if (authToken) {
    config.headers.Authorization = `Bearer ${authToken}`
  }

  try {
    const response = await fetch(`${API_BASE}${endpoint}`, config)

    if (!response.ok) {
      const errorData = await response
        .json()
        .catch(() => ({ message: 'Network error' }))
      throw new Error(errorData.message || `HTTP ${response.status}`)
    }

    return await response.json()
  } catch (error) {
    console.error('API Request failed:', error)
    throw error
  }
}

// Get CSRF Token
async function getCsrfToken () {
  try {
    const response = await apiRequest('/api/csrf-token')
    csrfToken = response.csrfToken
  } catch (error) {
    console.error('Failed to get CSRF token:', error)
  }
}

// Toast Notifications
function showToast (message, type = 'info') {
  const container = document.getElementById('toast-container')
  const toast = document.createElement('div')
  toast.className = `toast ${type}`

  const icons = {
    success: 'fas fa-check-circle',
    error: 'fas fa-exclamation-circle',
    warning: 'fas fa-exclamation-triangle',
    info: 'fas fa-info-circle'
  }

  toast.innerHTML = `
        <i class="toast-icon ${icons[type]}"></i>
        <span class="toast-message">${sanitizeHtml(message)}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `

  container.appendChild(toast)

  // Auto remove after 5 seconds
  setTimeout(() => {
    if (toast.parentElement) {
      toast.style.animation = 'slideOut 0.3s ease'
      setTimeout(() => toast.remove(), 300)
    }
  }, 5000)
}

// Loading State
function setLoading (isLoading) {
  elements.loading.classList.toggle('hidden', !isLoading)
}

// Password Strength Checker
function checkPasswordStrength (password) {
  const requirements = [
    /[a-z]/.test(password), // lowercase
    /[A-Z]/.test(password), // uppercase
    /\d/.test(password), // number
    /[@$!%*?&]/.test(password), // special char
    password.length >= 8 // length
  ]

  const strength = requirements.filter(Boolean).length
  const strengthFill = document.getElementById('strength-fill')
  const strengthText = document.getElementById('strength-text')

  if (!strengthFill || !strengthText) return

  const levels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong']
  const colors = ['#e74c3c', '#e67e22', '#f39c12', '#27ae60', '#2ecc71']

  strengthFill.style.width = `${(strength / 5) * 100}%`
  strengthFill.style.backgroundColor = colors[strength - 1] || colors[0]
  strengthText.textContent = levels[strength - 1] || levels[0]
  strengthText.style.color = colors[strength - 1] || colors[0]
}

// Password Toggle
function togglePassword (inputId) {
  const input = document.getElementById(inputId)
  const icon = input.nextElementSibling.nextElementSibling.querySelector('i')

  if (input.type === 'password') {
    input.type = 'text'
    icon.className = 'fas fa-eye-slash'
  } else {
    input.type = 'password'
    icon.className = 'fas fa-eye'
  }
}

// Auth Functions
function showLogin () {
  elements.loginForm.classList.remove('hidden')
  elements.registerForm.classList.add('hidden')
  elements.loginForm.reset()
}

function showRegister () {
  elements.registerForm.classList.remove('hidden')
  elements.loginForm.classList.add('hidden')
  elements.registerForm.reset()
}

async function register (event) {
  event.preventDefault()
  setLoading(true)

  const username = document.getElementById('register-username').value.trim()
  const email = document.getElementById('register-email').value.trim()
  const password = document.getElementById('register-password').value

  // Client-side validation
  if (!validateInput(username, 'username')) {
    showToast(
      'Username must be 3-30 characters with letters, numbers, and underscores only',
      'error'
    )
    setLoading(false)
    return
  }

  if (!validateInput(email, 'email')) {
    showToast('Please enter a valid email address', 'error')
    setLoading(false)
    return
  }

  if (!validateInput(password, 'password')) {
    showToast(
      'Password must be at least 8 characters with uppercase, lowercase, number, and special character',
      'error'
    )
    setLoading(false)
    return
  }

  try {
    await apiRequest('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, email, password })
    })

    showToast('Registration successful! Please sign in.', 'success')
    showLogin()
  } catch (error) {
    showToast(error.message, 'error')
  } finally {
    setLoading(false)
  }
}

async function login (event) {
  event.preventDefault()
  setLoading(true)

  const username = document.getElementById('login-username').value.trim()
  const password = document.getElementById('login-password').value

  if (!username || !password) {
    showToast('Please enter both username and password', 'error')
    setLoading(false)
    return
  }

  try {
    const response = await apiRequest('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    })

    authToken = response.token
    currentUser = response.user
    localStorage.setItem('authToken', authToken)
    localStorage.setItem('currentUser', JSON.stringify(currentUser))

    showApp()
    loadNotes()
    showToast('Login successful!', 'success')
  } catch (error) {
    showToast(error.message, 'error')
  } finally {
    setLoading(false)
  }
}

async function logout () {
  setLoading(true)

  try {
    await apiRequest('/api/auth/logout', { method: 'POST' })
  } catch (error) {
    console.error('Logout error:', error)
  }

  // Clear local storage and state
  localStorage.removeItem('authToken')
  localStorage.removeItem('currentUser')
  authToken = null
  currentUser = null
  notes = []

  showAuth()
  showToast('Logged out successfully', 'info')
  setLoading(false)
}

// UI Functions
function showAuth () {
  elements.authContainer.classList.remove('hidden')
  elements.mainApp.classList.add('hidden')
  showLogin()
}

function showApp () {
  elements.authContainer.classList.add('hidden')
  elements.mainApp.classList.remove('hidden')
  elements.usernameDisplay.textContent = currentUser?.username || 'User'
}

// Notes Functions
async function loadNotes () {
  try {
    setLoading(true)
    const response = await apiRequest('/api/notes')
    notes = response.notes || []
    filteredNotes = [...notes]
    renderNotes()
  } catch (error) {
    showToast('Failed to load notes: ' + error.message, 'error')
  } finally {
    setLoading(false)
  }
}

function renderNotes () {
  const container = elements.notesList

  if (filteredNotes.length === 0) {
    container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-sticky-note"></i>
                <h3>No notes found</h3>
                <p>${
                  notes.length === 0
                    ? 'Create your first note to get started'
                    : 'Try adjusting your search'
                }</p>
            </div>
        `
    return
  }

  container.innerHTML = filteredNotes
    .map(
      (note) => `
        <div class="note-item" data-id="${note.id}">
            <div class="note-header">
                <h3 class="note-title">${sanitizeHtml(note.title)}</h3>
                <div class="note-actions">
                    <button class="edit-btn" onclick="editNote(${
                      note.id
                    })" title="Edit">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="delete-btn" onclick="showDeleteModal(${
                      note.id
                    })" title="Delete">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
            <div class="note-content">${sanitizeHtml(note.content)}</div>
            <div class="note-meta">
                <span>Created: ${formatDate(note.created_at)}</span>
                <span>Updated: ${formatDate(note.updated_at)}</span>
            </div>
        </div>
    `
    )
    .join('')
}

function formatDate (dateString) {
  const date = new Date(dateString)
  return (
    date.toLocaleDateString() +
    ' ' +
    date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  )
}

function searchNotes () {
  const query = elements.searchInput.value.toLowerCase().trim()

  if (!query) {
    filteredNotes = [...notes]
  } else {
    filteredNotes = notes.filter(
      (note) =>
        note.title.toLowerCase().includes(query) ||
        note.content.toLowerCase().includes(query)
    )
  }

  renderNotes()
}

// Modal Functions
function showNoteModal (title = 'New Note', note = null) {
  elements.modalTitle.textContent = title
  elements.noteModal.classList.remove('hidden')

  if (note) {
    document.getElementById('note-title').value = note.title
    document.getElementById('note-content').value = note.content
    currentNoteId = note.id
  } else {
    elements.noteForm.reset()
    currentNoteId = null
  }

  document.getElementById('note-title').focus()
}

function closeModal () {
  elements.noteModal.classList.add('hidden')
  elements.noteForm.reset()
  currentNoteId = null
}

function showDeleteModal (noteId) {
  currentNoteId = noteId
  elements.deleteModal.classList.remove('hidden')
}

function closeDeleteModal () {
  elements.deleteModal.classList.add('hidden')
  currentNoteId = null
}

// Note CRUD Operations
async function saveNote (event) {
  event.preventDefault()
  setLoading(true)

  const title = document.getElementById('note-title').value.trim()
  const content = document.getElementById('note-content').value.trim()

  if (!title || !content) {
    showToast('Please fill in both title and content', 'error')
    setLoading(false)
    return
  }

  if (title.length > 200) {
    showToast('Title must be 200 characters or less', 'error')
    setLoading(false)
    return
  }

  if (content.length > 10000) {
    showToast('Content must be 10,000 characters or less', 'error')
    setLoading(false)
    return
  }

  try {
    const endpoint = currentNoteId
      ? `/api/notes/${currentNoteId}`
      : '/api/notes'
    const method = currentNoteId ? 'PUT' : 'POST'

    await apiRequest(endpoint, {
      method,
      body: JSON.stringify({ title, content })
    })

    closeModal()
    loadNotes()
    showToast(
      currentNoteId
        ? 'Note updated successfully!'
        : 'Note created successfully!',
      'success'
    )
  } catch (error) {
    showToast('Failed to save note: ' + error.message, 'error')
  } finally {
    setLoading(false)
  }
}

function editNote (noteId) {
  const note = notes.find((n) => n.id === noteId)
  if (note) {
    showNoteModal('Edit Note', note)
  }
}

async function deleteNote () {
  if (!currentNoteId) return

  setLoading(true)

  try {
    await apiRequest(`/api/notes/${currentNoteId}`, {
      method: 'DELETE'
    })

    closeDeleteModal()
    loadNotes()
    showToast('Note deleted successfully!', 'success')
  } catch (error) {
    showToast('Failed to delete note: ' + error.message, 'error')
  } finally {
    setLoading(false)
  }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', async () => {
  // Get CSRF token
  await getCsrfToken()

  // Check if user is already logged in
  const storedUser = localStorage.getItem('currentUser')
  if (authToken && storedUser) {
    try {
      currentUser = JSON.parse(storedUser)
      showApp()
      loadNotes()
    } catch (error) {
      console.error('Invalid stored user data:', error)
      localStorage.removeItem('authToken')
      localStorage.removeItem('currentUser')
      showAuth()
    }
  } else {
    showAuth()
  }

  // Form event listeners
  elements.loginForm.addEventListener('submit', login)
  elements.registerForm.addEventListener('submit', register)
  elements.noteForm.addEventListener('submit', saveNote)
  elements.logoutBtn.addEventListener('click', logout)
  elements.newNoteBtn.addEventListener('click', () => showNoteModal())
  elements.confirmDeleteBtn.addEventListener('click', deleteNote)

  // Search functionality
  elements.searchInput.addEventListener('input', searchNotes)

  // Password strength checker
  const passwordInput = document.getElementById('register-password')
  if (passwordInput) {
    passwordInput.addEventListener('input', (e) =>
      checkPasswordStrength(e.target.value)
    )
  }

  // Close modals on outside click
  elements.noteModal.addEventListener('click', (e) => {
    if (e.target === elements.noteModal) closeModal()
  })

  elements.deleteModal.addEventListener('click', (e) => {
    if (e.target === elements.deleteModal) closeDeleteModal()
  })

  // Handle keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    // Escape key closes modals
    if (e.key === 'Escape') {
      if (!elements.noteModal.classList.contains('hidden')) {
        closeModal()
      }
      if (!elements.deleteModal.classList.contains('hidden')) {
        closeDeleteModal()
      }
    }

    // Ctrl+N for new note (when logged in)
    if (
      e.ctrlKey &&
      e.key === 'n' &&
      !elements.mainApp.classList.contains('hidden')
    ) {
      e.preventDefault()
      showNoteModal()
    }
  })
})

// Global functions for dynamic HTML (exposed to window)
window.togglePassword = togglePassword
window.showLogin = showLogin
window.showRegister = showRegister
window.showDeleteModal = showDeleteModal
window.editNote = editNote

// Security: Clear sensitive data on page unload
window.addEventListener('beforeunload', () => {
  // Clear any sensitive form data
  const forms = document.querySelectorAll('form')
  forms.forEach((form) => {
    const passwordInputs = form.querySelectorAll('input[type="password"]')
    passwordInputs.forEach((input) => {
      input.value = ''
    })
  })
})
