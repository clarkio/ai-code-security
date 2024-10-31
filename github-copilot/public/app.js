document.addEventListener('DOMContentLoaded', () => {
  const noteForm = document.getElementById('note-form');
  const noteIdInput = document.getElementById('note-id');
  const titleInput = document.getElementById('title');
  const contentInput = document.getElementById('content');
  const notesContainer = document.getElementById('notes');

  const apiUrl = 'http://localhost:3000/notes';

  // Fetch and display notes
  const fetchNotes = async () => {
    const response = await fetch(apiUrl);
    const notes = await response.json();
    notesContainer.innerHTML = '';
    notes.forEach(note => {
      const noteElement = document.createElement('div');
      noteElement.classList.add('note');
      noteElement.innerHTML = `
              <h2>${note.title}</h2>
              <p>${note.content}</p>
              <button onclick="deleteNote('${note._id}')">Delete</button>
              <button onclick="editNote('${note._id}', '${note.title}', '${note.content}')">Edit</button>
          `;
      notesContainer.appendChild(noteElement);
    });
  };

  // Add or update note
  noteForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = noteIdInput.value;
    const title = titleInput.value;
    const content = contentInput.value;

    const note = { title, content };

    if (id) {
      await fetch(`${apiUrl}/${id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(note)
      });
    } else {
      await fetch(apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(note)
      });
    }

    noteForm.reset();
    fetchNotes();
  });

  // Delete note
  window.deleteNote = async (id) => {
    await fetch(`${apiUrl}/${id}`, {
      method: 'DELETE'
    });
    fetchNotes();
  };

  // Edit note
  window.editNote = (id, title, content) => {
    noteIdInput.value = id;
    titleInput.value = title;
    contentInput.value = content;
  };

  fetchNotes();
});
