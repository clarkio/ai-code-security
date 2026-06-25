"use strict";

/**
 * Client-side JS.
 *
 * SECURITY:
 *  - We read the CSRF token from a meta tag and send it as a header on every
 *    state-changing request. The server validates it.
 *  - We NEVER use innerHTML with user data — all DOM updates use textContent
 *    or createElement, preventing DOM-based XSS.
 *  - All user input is sent as JSON; the server re-validates & sanitizes.
 */

(function () {
  var csrfToken = "";
  var meta = document.querySelector('meta[name="csrf-token"]');
  if (meta) csrfToken = meta.getAttribute("content") || "";

  function showError(el, msg) {
    if (!el) return;
    el.textContent = msg; // textContent — never innerHTML
    el.hidden = false;
  }

  function clearError(el) {
    if (!el) return;
    el.textContent = "";
    el.hidden = true;
  }

  function api(method, url, body) {
    var opts = {
      method: method,
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "same-origin",
    };
    if (body) opts.body = JSON.stringify(body);
    if (["POST", "PUT", "PATCH", "DELETE"].indexOf(method) !== -1) {
      opts.headers["X-CSRF-Token"] = csrfToken;
    }
    return fetch(url, opts).then(function (res) {
      return res.json().then(function (data) {
        if (!res.ok) throw data;
        return data;
      });
    });
  }

  // --- Auth forms ---
  var loginForm = document.getElementById("loginForm");
  if (loginForm) {
    loginForm.addEventListener("submit", function (e) {
      e.preventDefault();
      var errEl = document.getElementById("formError");
      clearError(errEl);
      var data = {
        username: loginForm.username.value.trim(),
        password: loginForm.password.value,
      };
      api("POST", "/api/auth/login", data)
        .then(function () {
          window.location.href = "/notes";
        })
        .catch(function (err) {
          showError(errEl, (err && err.error) || "Login failed");
        });
    });
  }

  var registerForm = document.getElementById("registerForm");
  if (registerForm) {
    registerForm.addEventListener("submit", function (e) {
      e.preventDefault();
      var errEl = document.getElementById("formError");
      clearError(errEl);
      var data = {
        username: registerForm.username.value.trim(),
        password: registerForm.password.value,
      };
      api("POST", "/api/auth/register", data)
        .then(function () {
          window.location.href = "/notes";
        })
        .catch(function (err) {
          showError(errEl, (err && err.error) || "Registration failed");
        });
    });
  }

  var logoutBtn = document.getElementById("logoutBtn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", function () {
      api("POST", "/api/auth/logout").then(function () {
        window.location.href = "/login";
      });
    });
  }

  // --- Notes page ---
  var noteForm = document.getElementById("noteForm");
  if (!noteForm) return;

  var noteIdEl = document.getElementById("noteId");
  var titleEl = document.getElementById("noteTitle");
  var bodyEl = document.getElementById("noteBody");
  var errEl = document.getElementById("formError");

  noteForm.addEventListener("submit", function (e) {
    e.preventDefault();
    clearError(errEl);
    var id = noteIdEl.value;
    var data = { title: titleEl.value.trim(), body: bodyEl.value };
    var method = id ? "PUT" : "POST";
    var url = id ? "/api/notes/" + encodeURIComponent(id) : "/api/notes";
    api(method, url, data)
      .then(function () {
        window.location.reload();
      })
      .catch(function (err) {
        showError(errEl, (err && err.error) || "Save failed");
      });
  });

  document.getElementById("clearBtn").addEventListener("click", function () {
    noteIdEl.value = "";
    titleEl.value = "";
    bodyEl.value = "";
    document.getElementById("editorTitle").textContent = "New Note";
    clearError(errEl);
  });

  // Load note into editor — uses textContent, never innerHTML
  var loadButtons = document.querySelectorAll(".note-load");
  loadButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      var id = btn.getAttribute("data-id");
      api("GET", "/api/notes/" + encodeURIComponent(id))
        .then(function (res) {
          var note = res.note;
          noteIdEl.value = String(note.id);
          titleEl.value = note.title;
          bodyEl.value = note.body;
          document.getElementById("editorTitle").textContent =
            "Edit Note #" + note.id;
        })
        .catch(function (err) {
          showError(errEl, (err && err.error) || "Failed to load note");
        });
    });
  });

  // Delete note
  var deleteButtons = document.querySelectorAll(".note-delete");
  deleteButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      var id = btn.getAttribute("data-id");
      if (!confirm("Delete this note?")) return;
      api("DELETE", "/api/notes/" + encodeURIComponent(id))
        .then(function () {
          window.location.reload();
        })
        .catch(function (err) {
          showError(errEl, (err && err.error) || "Delete failed");
        });
    });
  });
})();
