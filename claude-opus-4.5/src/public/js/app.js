/**
 * Secure Notes Application - Frontend JavaScript
 * Security: XSS prevention, secure token storage, input sanitization
 */

(function () {
  "use strict";

  // ============================================
  // CONFIGURATION
  // ============================================

  const API_BASE = "/api";
  const TOKEN_KEY = "accessToken";
  const REFRESH_TOKEN_KEY = "refreshToken";

  // ============================================
  // STATE
  // ============================================

  let currentUser = null;
  let editingNoteId = null;
  let currentPage = 0;
  const pageSize = 10;

  // ============================================
  // SECURITY UTILITIES
  // ============================================

  /**
   * HTML escape to prevent XSS
   * Use this when inserting user content into the DOM
   */
  function escapeHtml(unsafe) {
    if (typeof unsafe !== "string") return "";
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  /**
   * Create text node (safe from XSS)
   */
  function createTextNode(text) {
    return document.createTextNode(text || "");
  }

  /**
   * Set element text content safely
   */
  function setTextContent(element, text) {
    if (element) {
      element.textContent = text || "";
    }
  }

  // ============================================
  // TOKEN MANAGEMENT (Secure Storage)
  // ============================================

  /**
   * Store tokens securely
   * Note: For maximum security, access tokens should be in memory only
   * Refresh tokens can be in localStorage (they're only valid for token refresh)
   */
  function storeTokens(accessToken, refreshToken) {
    // Store access token in memory (more secure than localStorage)
    sessionStorage.setItem(TOKEN_KEY, accessToken);

    if (refreshToken) {
      // Refresh token in localStorage for persistence
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
    }
  }

  function getAccessToken() {
    return sessionStorage.getItem(TOKEN_KEY);
  }

  function getRefreshToken() {
    return localStorage.getItem(REFRESH_TOKEN_KEY);
  }

  function clearTokens() {
    sessionStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
  }

  // ============================================
  // API UTILITIES
  // ============================================

  /**
   * Make authenticated API request
   */
  async function apiRequest(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;

    const headers = {
      "Content-Type": "application/json",
      ...options.headers,
    };

    const token = getAccessToken();
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        credentials: "same-origin", // Include cookies
      });

      // Handle token expiration
      if (response.status === 401) {
        const data = await response.json();

        if (data.code === "TOKEN_EXPIRED") {
          // Try to refresh token
          const refreshed = await refreshAccessToken();
          if (refreshed) {
            // Retry original request
            headers["Authorization"] = `Bearer ${getAccessToken()}`;
            return fetch(url, {
              ...options,
              headers,
              credentials: "same-origin",
            });
          }
        }

        // Refresh failed or other auth error - logout
        handleLogout();
        throw new Error("Authentication required");
      }

      return response;
    } catch (error) {
      console.error("API request failed:", error);
      throw error;
    }
  }

  /**
   * Refresh access token
   */
  async function refreshAccessToken() {
    const refreshToken = getRefreshToken();
    if (!refreshToken) return false;

    try {
      const response = await fetch(`${API_BASE}/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken }),
        credentials: "same-origin",
      });

      if (response.ok) {
        const data = await response.json();
        storeTokens(data.accessToken, data.refreshToken);
        return true;
      }

      return false;
    } catch (error) {
      console.error("Token refresh failed:", error);
      return false;
    }
  }

  // ============================================
  // UI HELPERS
  // ============================================

  function showElement(element) {
    if (element) element.classList.remove("hidden");
  }

  function hideElement(element) {
    if (element) element.classList.add("hidden");
  }

  function showError(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) {
      setTextContent(element, message);
    }
  }

  function clearError(elementId) {
    showError(elementId, "");
  }

  function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  // ============================================
  // AUTH HANDLERS
  // ============================================

  async function handleLogin(e) {
    e.preventDefault();

    const form = e.target;
    const submitBtn = form.querySelector('button[type="submit"]');
    const username = form.querySelector("#login-username").value.trim();
    const password = form.querySelector("#login-password").value;

    clearError("login-error");
    submitBtn.disabled = true;

    try {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
        credentials: "same-origin",
      });

      const data = await response.json();

      if (response.ok) {
        storeTokens(data.accessToken, data.refreshToken);
        currentUser = data.user;
        showNotesSection();
        form.reset();
      } else {
        showError("login-error", data.error || "Login failed");
      }
    } catch (error) {
      showError("login-error", "Network error. Please try again.");
    } finally {
      submitBtn.disabled = false;
    }
  }

  async function handleRegister(e) {
    e.preventDefault();

    const form = e.target;
    const submitBtn = form.querySelector('button[type="submit"]');
    const username = form.querySelector("#register-username").value.trim();
    const email = form.querySelector("#register-email").value.trim();
    const password = form.querySelector("#register-password").value;
    const confirmPassword = form.querySelector(
      "#register-confirm-password"
    ).value;

    clearError("register-error");

    // Client-side validation
    if (password !== confirmPassword) {
      showError("register-error", "Passwords do not match");
      return;
    }

    submitBtn.disabled = true;

    try {
      const response = await fetch(`${API_BASE}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email, password, confirmPassword }),
        credentials: "same-origin",
      });

      const data = await response.json();

      if (response.ok) {
        storeTokens(data.accessToken, data.refreshToken);
        currentUser = data.user;
        showNotesSection();
        form.reset();
      } else {
        const errorMsg = data.details
          ? data.details.map((d) => d.message).join(". ")
          : data.error || "Registration failed";
        showError("register-error", errorMsg);
      }
    } catch (error) {
      showError("register-error", "Network error. Please try again.");
    } finally {
      submitBtn.disabled = false;
    }
  }

  async function handleLogout() {
    try {
      const refreshToken = getRefreshToken();
      await apiRequest("/auth/logout", {
        method: "POST",
        body: JSON.stringify({ refreshToken }),
      });
    } catch (error) {
      // Logout anyway even if API call fails
    }

    clearTokens();
    currentUser = null;
    showAuthSection();
  }

  // ============================================
  // NOTES HANDLERS
  // ============================================

  async function loadNotes(page = 0, search = "") {
    const notesList = document.getElementById("notes-list");
    setTextContent(notesList, "Loading...");
    notesList.className = "notes-list loading";

    try {
      let endpoint = `/notes?limit=${pageSize}&offset=${page * pageSize}`;
      if (search) {
        endpoint = `/notes/search?q=${encodeURIComponent(
          search
        )}&limit=${pageSize}&offset=${page * pageSize}`;
      }

      const response = await apiRequest(endpoint);

      if (!response.ok) {
        throw new Error("Failed to load notes");
      }

      const data = await response.json();
      renderNotes(data.notes);

      if (data.pagination) {
        renderPagination(data.pagination, page, search);
      }
    } catch (error) {
      setTextContent(notesList, "Failed to load notes. Please try again.");
      notesList.className = "notes-list";
    }
  }

  function renderNotes(notes) {
    const notesList = document.getElementById("notes-list");
    notesList.className = "notes-list";
    notesList.innerHTML = "";

    if (notes.length === 0) {
      const emptyState = document.createElement("div");
      emptyState.className = "empty-state";

      const p1 = document.createElement("p");
      setTextContent(p1, "No notes yet");
      emptyState.appendChild(p1);

      const p2 = document.createElement("p");
      setTextContent(p2, "Create your first note above!");
      emptyState.appendChild(p2);

      notesList.appendChild(emptyState);
      return;
    }

    notes.forEach((note) => {
      const card = createNoteCard(note);
      notesList.appendChild(card);
    });
  }

  function createNoteCard(note) {
    const card = document.createElement("div");
    card.className = "note-card";
    card.setAttribute("role", "listitem");
    card.dataset.noteId = note.id;

    // Header
    const header = document.createElement("div");
    header.className = "note-card-header";

    const title = document.createElement("h3");
    title.className = "note-title";
    setTextContent(title, note.title);
    header.appendChild(title);

    // Actions
    const actions = document.createElement("div");
    actions.className = "note-actions";

    const editBtn = document.createElement("button");
    editBtn.className = "btn btn-small btn-secondary";
    setTextContent(editBtn, "Edit");
    editBtn.onclick = () => startEditNote(note);
    actions.appendChild(editBtn);

    const deleteBtn = document.createElement("button");
    deleteBtn.className = "btn btn-small btn-danger";
    setTextContent(deleteBtn, "Delete");
    deleteBtn.onclick = () => deleteNote(note.id);
    actions.appendChild(deleteBtn);

    header.appendChild(actions);
    card.appendChild(header);

    // Content
    const content = document.createElement("p");
    content.className = "note-content";
    // Truncate content for display
    const displayContent =
      note.content.length > 200
        ? note.content.substring(0, 200) + "..."
        : note.content;
    setTextContent(content, displayContent);
    card.appendChild(content);

    // Meta
    const meta = document.createElement("div");
    meta.className = "note-meta";
    setTextContent(
      meta,
      `Updated: ${formatDate(note.updated_at || note.updatedAt)}`
    );
    card.appendChild(meta);

    return card;
  }

  function renderPagination(pagination, currentPageNum, search) {
    const paginationEl = document.getElementById("pagination");
    paginationEl.innerHTML = "";

    const totalPages = Math.ceil(pagination.total / pageSize);
    if (totalPages <= 1) return;

    // Previous button
    const prevBtn = document.createElement("button");
    setTextContent(prevBtn, "← Previous");
    prevBtn.disabled = currentPageNum === 0;
    prevBtn.onclick = () => {
      currentPage = currentPageNum - 1;
      loadNotes(currentPage, search);
    };
    paginationEl.appendChild(prevBtn);

    // Page info
    const pageInfo = document.createElement("span");
    setTextContent(pageInfo, `Page ${currentPageNum + 1} of ${totalPages}`);
    pageInfo.style.padding = "0.5rem 1rem";
    paginationEl.appendChild(pageInfo);

    // Next button
    const nextBtn = document.createElement("button");
    setTextContent(nextBtn, "Next →");
    nextBtn.disabled = !pagination.hasMore;
    nextBtn.onclick = () => {
      currentPage = currentPageNum + 1;
      loadNotes(currentPage, search);
    };
    paginationEl.appendChild(nextBtn);
  }

  async function handleNoteSubmit(e) {
    e.preventDefault();

    const form = e.target;
    const submitBtn = form.querySelector("#save-note-btn");
    const title = form.querySelector("#note-title").value.trim();
    const content = form.querySelector("#note-content").value.trim();
    const noteId = form.querySelector("#note-id").value;

    clearError("note-error");

    if (!title || !content) {
      showError("note-error", "Title and content are required");
      return;
    }

    submitBtn.disabled = true;

    try {
      let response;

      if (noteId) {
        // Update existing note
        response = await apiRequest(`/notes/${noteId}`, {
          method: "PUT",
          body: JSON.stringify({ title, content }),
        });
      } else {
        // Create new note
        response = await apiRequest("/notes", {
          method: "POST",
          body: JSON.stringify({ title, content }),
        });
      }

      if (response.ok) {
        form.reset();
        cancelEdit();
        currentPage = 0;
        loadNotes(0);
      } else {
        const data = await response.json();
        const errorMsg = data.details
          ? data.details.map((d) => d.message).join(". ")
          : data.error || "Failed to save note";
        showError("note-error", errorMsg);
      }
    } catch (error) {
      showError("note-error", "Network error. Please try again.");
    } finally {
      submitBtn.disabled = false;
    }
  }

  function startEditNote(note) {
    editingNoteId = note.id;

    document.getElementById("note-title").value = note.title;
    document.getElementById("note-content").value = note.content;
    document.getElementById("note-id").value = note.id;

    setTextContent(document.getElementById("save-note-btn"), "Update Note");
    showElement(document.getElementById("cancel-edit-btn"));

    // Scroll to form
    document.getElementById("note-form").scrollIntoView({ behavior: "smooth" });
  }

  function cancelEdit() {
    editingNoteId = null;

    document.getElementById("note-form").reset();
    document.getElementById("note-id").value = "";

    setTextContent(document.getElementById("save-note-btn"), "Save Note");
    hideElement(document.getElementById("cancel-edit-btn"));
  }

  async function deleteNote(noteId) {
    if (!confirm("Are you sure you want to delete this note?")) {
      return;
    }

    try {
      const response = await apiRequest(`/notes/${noteId}`, {
        method: "DELETE",
      });

      if (response.ok) {
        // If we were editing this note, cancel edit
        if (editingNoteId === noteId) {
          cancelEdit();
        }
        loadNotes(currentPage);
      } else {
        const data = await response.json();
        alert(data.error || "Failed to delete note");
      }
    } catch (error) {
      alert("Network error. Please try again.");
    }
  }

  // ============================================
  // SEARCH
  // ============================================

  let searchTimeout = null;

  function handleSearch(e) {
    const searchTerm = e.target.value.trim();

    // Debounce search
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      currentPage = 0;
      loadNotes(0, searchTerm);
    }, 300);
  }

  // ============================================
  // SECTION MANAGEMENT
  // ============================================

  function showAuthSection() {
    hideElement(document.getElementById("notes-section"));
    showElement(document.getElementById("auth-section"));

    // Reset forms
    document.getElementById("login-form").reset();
    document.getElementById("register-form").reset();
    clearError("login-error");
    clearError("register-error");
  }

  function showNotesSection() {
    hideElement(document.getElementById("auth-section"));
    showElement(document.getElementById("notes-section"));

    // Show username
    if (currentUser) {
      setTextContent(
        document.getElementById("user-display"),
        `Welcome, ${currentUser.username}`
      );
    }

    // Load notes
    currentPage = 0;
    loadNotes(0);
  }

  // ============================================
  // TAB SWITCHING
  // ============================================

  function switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll(".tab-btn").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.tab === tabName);
    });

    // Show/hide forms
    if (tabName === "login") {
      showElement(document.getElementById("login-form"));
      hideElement(document.getElementById("register-form"));
    } else {
      hideElement(document.getElementById("login-form"));
      showElement(document.getElementById("register-form"));
    }

    clearError("login-error");
    clearError("register-error");
  }

  // ============================================
  // INITIALIZATION
  // ============================================

  async function checkAuth() {
    const token = getAccessToken();
    if (!token) {
      // Try to refresh
      const refreshed = await refreshAccessToken();
      if (!refreshed) {
        showAuthSection();
        return;
      }
    }

    try {
      const response = await apiRequest("/auth/me");

      if (response.ok) {
        const data = await response.json();
        currentUser = data.user;
        showNotesSection();
      } else {
        clearTokens();
        showAuthSection();
      }
    } catch (error) {
      clearTokens();
      showAuthSection();
    }
  }

  function initEventListeners() {
    // Tab switching
    document.querySelectorAll(".tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => switchTab(btn.dataset.tab));
    });

    // Auth forms
    document
      .getElementById("login-form")
      .addEventListener("submit", handleLogin);
    document
      .getElementById("register-form")
      .addEventListener("submit", handleRegister);

    // Logout
    document
      .getElementById("logout-btn")
      .addEventListener("click", handleLogout);

    // Note form
    document
      .getElementById("note-form")
      .addEventListener("submit", handleNoteSubmit);
    document
      .getElementById("cancel-edit-btn")
      .addEventListener("click", cancelEdit);

    // Search
    document
      .getElementById("search-input")
      .addEventListener("input", handleSearch);
  }

  // Start app
  document.addEventListener("DOMContentLoaded", () => {
    initEventListeners();
    checkAuth();
  });
})();
