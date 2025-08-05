// This file contains client-side JavaScript for handling user interactions.
// It includes functions for creating, updating, and deleting notes securely.

document.addEventListener('DOMContentLoaded', () => {
    const noteForm = document.getElementById('note-form');
    const noteList = document.getElementById('note-list');

    // Function to create a new note
    noteForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const noteContent = document.getElementById('note-content').value;

        try {
            const response = await fetch('/notes', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ content: noteContent }),
            });

            if (response.ok) {
                const newNote = await response.json();
                addNoteToList(newNote);
                noteForm.reset();
            } else {
                console.error('Error creating note:', response.statusText);
            }
        } catch (error) {
            console.error('Error:', error);
        }
    });

    // Function to add a note to the list
    function addNoteToList(note) {
        const noteItem = document.createElement('li');
        noteItem.textContent = note.content;

        // Create update button
        const updateButton = document.createElement('button');
        updateButton.textContent = 'Update';
        updateButton.addEventListener('click', () => updateNote(note.id));

        // Create delete button
        const deleteButton = document.createElement('button');
        deleteButton.textContent = 'Delete';
        deleteButton.addEventListener('click', () => deleteNote(note.id));

        noteItem.appendChild(updateButton);
        noteItem.appendChild(deleteButton);
        noteList.appendChild(noteItem);
    }

    // Function to update a note
    async function updateNote(noteId) {
        const newContent = prompt('Enter new content:');
        if (newContent) {
            try {
                const response = await fetch(`/notes/${noteId}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ content: newContent }),
                });

                if (response.ok) {
                    location.reload(); // Reload to get updated notes
                } else {
                    console.error('Error updating note:', response.statusText);
                }
            } catch (error) {
                console.error('Error:', error);
            }
        }
    }

    // Function to delete a note
    async function deleteNote(noteId) {
        if (confirm('Are you sure you want to delete this note?')) {
            try {
                const response = await fetch(`/notes/${noteId}`, {
                    method: 'DELETE',
                });

                if (response.ok) {
                    location.reload(); // Reload to get updated notes
                } else {
                    console.error('Error deleting note:', response.statusText);
                }
            } catch (error) {
                console.error('Error:', error);
            }
        }
    }
});