document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('note-form');
    const contentInput = document.getElementById('note-content');
    const notesList = document.getElementById('notes-list');
    const submitBtn = document.getElementById('submit-btn');
    const errorMsg = document.getElementById('form-error');

    // Load initial notes
    fetchNotes();

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const content = contentInput.value.trim();
        if (!content) return;

        try {
            submitBtn.disabled = true;
            submitBtn.textContent = 'Adding...';
            errorMsg.textContent = ''; // Clear prior errors

            const response = await fetch('/api/notes', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ content })
            });

            if (!response.ok) {
                const data = await response.json();
                throw new Error(data.error || 'Failed to add note');
            }

            const newNote = await response.json();

            // 100% SECURE DOM INJECTION
            // The note is injected at the top without touching existing elements
            const noteEl = createNoteElement(newNote);
            notesList.insertBefore(noteEl, notesList.firstChild);

            contentInput.value = ''; // Reset form
        } catch (err) {
            console.error('Add note error:', err);
            errorMsg.textContent = err.message || 'An error occurred while saving the note.';
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Add Note';
        }
    });

    async function fetchNotes() {
        try {
            const loadingEl = document.getElementById('loading');
            const response = await fetch('/api/notes');
            if (!response.ok) throw new Error('Failed to fetch notes');

            const notes = await response.json();

            // Clear loading and existing notes
            if (loadingEl) loadingEl.remove();

            // 100% SECURE CLEARING
            // Much safer than innerHTML = ''
            while (notesList.firstChild) {
                notesList.removeChild(notesList.firstChild);
            }

            if (notes.length === 0) {
                const emptyMsg = document.createElement('div');
                emptyMsg.className = 'empty-state';
                emptyMsg.textContent = 'No notes yet. Create one securely above!';
                notesList.appendChild(emptyMsg);
                return;
            }

            // DocumentFragment is more performant than inserting one by one
            const fragment = document.createDocumentFragment();
            notes.forEach(note => {
                fragment.appendChild(createNoteElement(note));
            });
            notesList.appendChild(fragment);

        } catch (err) {
            console.error('Fetch notes error:', err);
            notesList.textContent = 'Failed to safely load notes. Please reload.';
        }
    }

    // ==========================================
    // 100% SECURE DOM CREATION
    // ==========================================
    // This function guarantees XSS protection by ONLY using standard DOM API text setting.
    // It NEVER evaluates strings as raw HTML (avoids innerHTML, outerHTML, insertAdjacentHTML).
    function createNoteElement(note) {
        const card = document.createElement('div');
        card.className = 'note-card';
        card.dataset.id = note.id;

        const contentElem = document.createElement('p');
        contentElem.className = 'note-content';
        // SECURE: textContent ensures that ANY HTML tags are treated generically as characters, not executed.
        // E.g., `<script>alert(1)</script>` becomes literal text string.
        contentElem.textContent = note.content;

        const metaElem = document.createElement('div');
        metaElem.className = 'note-meta';

        const dateElem = document.createElement('span');
        dateElem.className = 'note-date';
        const d = new Date(note.created_at);
        dateElem.textContent = d.toLocaleString();

        const actionsElem = document.createElement('div');
        actionsElem.className = 'note-actions';

        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'btn-delete';
        // SECURE: textContent instead of innerHTML
        deleteBtn.textContent = 'Delete';

        // Use an actual event listener rather than an inline `onclick="..."` string attribute
        deleteBtn.addEventListener('click', async () => {
            if (confirm('Are you sure you want to securely delete this note?')) {
                try {
                    deleteBtn.disabled = true;
                    deleteBtn.textContent = '...';

                    const response = await fetch(`/api/notes/${note.id}`, { method: 'DELETE' });
                    if (!response.ok) throw new Error('Delete failed');

                    card.remove(); // Remove element securely from DOM
                } catch (err) {
                    console.error('Delete error', err);
                    alert('Error deleting note securely.');
                    deleteBtn.disabled = false;
                    deleteBtn.textContent = 'Delete';
                }
            }
        });

        actionsElem.appendChild(deleteBtn);
        metaElem.appendChild(dateElem);
        metaElem.appendChild(actionsElem);

        card.appendChild(contentElem);
        card.appendChild(metaElem);

        return card;
    }
});
