async function loadNotes() {
  const res = await fetch('/api/notes');
  const notes = await res.json();
  const list = document.getElementById('notes');
  list.innerHTML = '';
  notes.forEach(n => {
    const li = document.createElement('li');
    li.innerHTML = `<strong>${n.title}</strong> - ${n.content}
      <button data-id="${n.id}" class="edit">Edit</button>
      <button data-id="${n.id}" class="delete">Delete</button>`;
    list.appendChild(li);
  });
}

document.getElementById('note-form').addEventListener('submit', async e => {
  e.preventDefault();
  const id = document.getElementById('note-id').value;
  const title = document.getElementById('title').value;
  const content = document.getElementById('content').value;
  const method = id ? 'PUT' : 'POST';
  const url = id ? '/api/notes/' + id : '/api/notes';
  await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title, content })
  });
  document.getElementById('note-id').value = '';
  document.getElementById('title').value = '';
  document.getElementById('content').value = '';
  loadNotes();
});

document.getElementById('notes').addEventListener('click', async e => {
  if (e.target.classList.contains('edit')) {
    const id = e.target.getAttribute('data-id');
    const res = await fetch('/api/notes');
    const notes = await res.json();
    const note = notes.find(n => n.id === id);
    document.getElementById('note-id').value = note.id;
    document.getElementById('title').value = note.title;
    document.getElementById('content').value = note.content;
  } else if (e.target.classList.contains('delete')) {
    const id = e.target.getAttribute('data-id');
    await fetch('/api/notes/' + id, { method: 'DELETE' });
    loadNotes();
  }
});

loadNotes();
