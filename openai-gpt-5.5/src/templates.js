export function renderLogin({ csrfToken, error = null }) {
  return layout({
    body: `
      <section class="auth-panel">
        <h1>Sign in</h1>
        ${renderErrors(error ? [error] : [])}
        <form method="post" action="/login" novalidate>
          ${csrfField(csrfToken)}
          <label>
            <span>Username</span>
            <input name="username" autocomplete="username" required minlength="3" maxlength="40">
          </label>
          <label>
            <span>Password</span>
            <input type="password" name="password" autocomplete="current-password" required minlength="12" maxlength="128">
          </label>
          <button type="submit">Sign in</button>
        </form>
        <p class="muted">Need an account? <a href="/register">Create one</a>.</p>
      </section>
    `,
    title: 'Sign in'
  });
}

export function renderRegister({ csrfToken, errors = [], values = {} }) {
  return layout({
    body: `
      <section class="auth-panel">
        <h1>Create account</h1>
        ${renderErrors(errors)}
        <form method="post" action="/register" novalidate>
          ${csrfField(csrfToken)}
          <label>
            <span>Username</span>
            <input name="username" autocomplete="username" required minlength="3" maxlength="40" value="${escapeHtml(values.username || '')}">
          </label>
          <label>
            <span>Password</span>
            <input type="password" name="password" autocomplete="new-password" required minlength="12" maxlength="128">
          </label>
          <button type="submit">Create account</button>
        </form>
        <p class="muted">Already have an account? <a href="/login">Sign in</a>.</p>
      </section>
    `,
    title: 'Create account'
  });
}

export function renderNotes({ csrfToken, notes, user }) {
  return layout({
    body: `
      ${appHeader({ csrfToken, user })}
      <main class="shell">
        <div class="page-title">
          <div>
            <p class="eyebrow">Private notes</p>
            <h1>Your notes</h1>
          </div>
          <a class="button" href="/notes/new">New note</a>
        </div>
        <section class="notes-list">
          ${notes.length ? notes.map((note) => noteCard({ csrfToken, note })).join('') : emptyState()}
        </section>
      </main>
    `,
    title: 'Your notes'
  });
}

export function renderNoteForm({ csrfToken, errors = [], note = {}, mode }) {
  const isEdit = mode === 'edit';
  const action = isEdit ? `/notes/${encodeURIComponent(note.id)}` : '/notes';

  return layout({
    body: `
      ${appHeader({ csrfToken, user: note.user })}
      <main class="shell narrow">
        <div class="page-title">
          <div>
            <p class="eyebrow">${isEdit ? 'Update note' : 'New note'}</p>
            <h1>${isEdit ? 'Edit note' : 'Create note'}</h1>
          </div>
          <a class="secondary-link" href="/notes">Back</a>
        </div>
        ${renderErrors(errors)}
        <form class="note-form" method="post" action="${action}" novalidate>
          ${csrfField(csrfToken)}
          <label>
            <span>Title</span>
            <input name="title" required maxlength="120" value="${escapeHtml(note.title || '')}">
          </label>
          <label>
            <span>Body</span>
            <textarea name="body" rows="12" maxlength="5000">${escapeHtml(note.body || '')}</textarea>
          </label>
          <div class="form-actions">
            <button type="submit">${isEdit ? 'Save changes' : 'Create note'}</button>
            <a class="secondary-link" href="/notes">Cancel</a>
          </div>
        </form>
      </main>
    `,
    title: isEdit ? 'Edit note' : 'New note'
  });
}

export function renderErrorPage({ csrfToken = null, message, status, title, user = null }) {
  return layout({
    body: `
      ${user ? appHeader({ csrfToken, user }) : ''}
      <main class="shell narrow">
        <section class="auth-panel">
          <p class="eyebrow">${status}</p>
          <h1>${escapeHtml(title)}</h1>
          <p>${escapeHtml(message)}</p>
          <a class="button" href="${user ? '/notes' : '/login'}">${user ? 'Back to notes' : 'Sign in'}</a>
        </section>
      </main>
    `,
    title
  });
}

function layout({ body, title }) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(title)} | Secure Notes</title>
    <link rel="stylesheet" href="/assets/styles.css">
  </head>
  <body>
    ${body}
  </body>
</html>`;
}

function appHeader({ csrfToken, user }) {
  return `
    <header class="topbar">
      <a class="brand" href="/notes">Secure Notes</a>
      <div class="topbar-actions">
        <span class="username">${escapeHtml(user.username)}</span>
        <form method="post" action="/logout">
          ${csrfField(csrfToken)}
          <button class="link-button" type="submit">Sign out</button>
        </form>
      </div>
    </header>
  `;
}

function noteCard({ csrfToken, note }) {
  return `
    <article class="note-card">
      <div>
        <h2>${escapeHtml(note.title)}</h2>
        <p class="note-body">${escapeHtml(note.body || 'No body text.')}</p>
        <p class="muted">Updated ${escapeHtml(formatDate(note.updated_at))}</p>
      </div>
      <div class="note-actions">
        <a class="secondary-link" href="/notes/${encodeURIComponent(note.id)}/edit">Edit</a>
        <form method="post" action="/notes/${encodeURIComponent(note.id)}/delete">
          ${csrfField(csrfToken)}
          <button class="danger-link" type="submit">Delete</button>
        </form>
      </div>
    </article>
  `;
}

function emptyState() {
  return `
    <section class="empty-state">
      <h2>No notes yet</h2>
      <p>Create your first note when you are ready.</p>
      <a class="button" href="/notes/new">New note</a>
    </section>
  `;
}

function renderErrors(errors) {
  if (!errors.length) return '';
  return `
    <div class="errors" role="alert">
      ${errors.map((error) => `<p>${escapeHtml(error)}</p>`).join('')}
    </div>
  `;
}

function csrfField(csrfToken) {
  return `<input type="hidden" name="_csrf" value="${escapeHtml(csrfToken || '')}">`;
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'recently';
  return new Intl.DateTimeFormat('en', {
    dateStyle: 'medium',
    timeStyle: 'short'
  }).format(date);
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
