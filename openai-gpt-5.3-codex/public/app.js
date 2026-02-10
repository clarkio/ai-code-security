const form = document.querySelector("#note-form");
const titleInput = document.querySelector("#title");
const contentInput = document.querySelector("#content");
const notesList = document.querySelector("#notes-list");
const statusText = document.querySelector("#status");
const formTitle = document.querySelector("#form-title");
const cancelBtn = document.querySelector("#cancel-btn");

let editingId = null;

function setStatus(message, isError = false) {
  statusText.textContent = message;
  statusText.className = isError ? "error" : "ok";
}

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(path, { ...options, headers });

  if (response.status === 204) {
    return null;
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || "Request failed");
  }
  return data;
}

function resetForm() {
  editingId = null;
  form.reset();
  formTitle.textContent = "Create Note";
  cancelBtn.hidden = true;
}

function renderNotes(notes) {
  notesList.textContent = "";

  if (notes.length === 0) {
    const empty = document.createElement("li");
    empty.textContent = "No notes yet.";
    notesList.append(empty);
    return;
  }

  for (const note of notes) {
    const item = document.createElement("li");
    item.className = "note-item";

    const title = document.createElement("h3");
    title.textContent = note.title;

    const meta = document.createElement("p");
    meta.className = "meta";
    meta.textContent = `Updated: ${new Date(note.updated_at).toLocaleString()}`;

    const content = document.createElement("pre");
    content.textContent = note.content;

    const actions = document.createElement("div");
    actions.className = "actions";

    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "secondary";
    editBtn.textContent = "Edit";
    editBtn.addEventListener("click", () => {
      editingId = note.id;
      titleInput.value = note.title;
      contentInput.value = note.content;
      formTitle.textContent = "Update Note";
      cancelBtn.hidden = false;
      titleInput.focus();
    });

    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "danger";
    deleteBtn.textContent = "Delete";
    deleteBtn.addEventListener("click", async () => {
      if (!window.confirm("Delete this note?")) {
        return;
      }
      try {
        await request(`/api/notes/${note.id}`, { method: "DELETE" });
        setStatus("Note deleted.");
        await loadNotes();
      } catch (error) {
        setStatus(error.message, true);
      }
    });

    actions.append(editBtn, deleteBtn);
    item.append(title, meta, content, actions);
    notesList.append(item);
  }
}

async function loadNotes() {
  const data = await request("/api/notes?limit=100&offset=0");
  renderNotes(data.notes);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const payload = {
    title: titleInput.value.trim(),
    content: contentInput.value.trim(),
  };

  try {
    if (editingId) {
      await request(`/api/notes/${editingId}`, {
        method: "PUT",
        body: JSON.stringify(payload),
      });
      setStatus("Note updated.");
    } else {
      await request("/api/notes", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setStatus("Note created.");
    }
    resetForm();
    await loadNotes();
  } catch (error) {
    setStatus(error.message, true);
  }
});

cancelBtn.addEventListener("click", () => {
  resetForm();
});

loadNotes()
  .then(() => setStatus("Loaded notes."))
  .catch((error) => setStatus(error.message, true));
