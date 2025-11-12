class SecureNotesApp {
    constructor() {
        this.notes = [];
        this.tags = [];
        this.csrfToken = null;
        this.currentEditingId = null;
        
        this.init();
    }

    async init() {
        try {
            await this.getCsrfToken();
            await this.loadNotes();
            await this.loadTags();
            this.setupEventListeners();
            this.hideLoading();
        } catch (error) {
            console.error('Failed to initialize app:', error);
            this.showToast('Failed to initialize application', 'error');
        }
    }

    async getCsrfToken() {
        try {
            const response = await fetch('/api/csrf-token');
            const data = await response.json();
            this.csrfToken = data.csrfToken;
        } catch (error) {
            console.error('Failed to get CSRF token:', error);
            throw error;
        }
    }

    setupEventListeners() {
        // Search functionality
        document.getElementById('searchInput').addEventListener('input', (e) => {
            this.filterNotes();
        });

        // Tag filter
        document.getElementById('tagFilter').addEventListener('change', (e) => {
            this.filterNotes();
        });

        // New note button
        document.getElementById('newNoteBtn').addEventListener('click', () => {
            this.openNoteModal();
        });

        // Note form submission
        document.getElementById('noteForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.saveNote();
        });

        // Close modal on background click
        document.getElementById('noteModal').addEventListener('click', (e) => {
            if (e.target.id === 'noteModal') {
                this.closeNoteModal();
            }
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeNoteModal();
            }
            if (e.ctrlKey && e.key === 'n') {
                e.preventDefault();
                this.openNoteModal();
            }
        });
    }

    async loadNotes() {
        try {
            const response = await fetch('/api/notes');
            const data = await response.json();
            
            if (data.success) {
                this.notes = data.data;
                this.renderNotes();
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            console.error('Failed to load notes:', error);
            this.showToast('Failed to load notes', 'error');
        }
    }

    async loadTags() {
        try {
            const response = await fetch('/api/notes/tags');
            const data = await response.json();
            
            if (data.success) {
                this.tags = data.data;
                this.renderTagFilter();
            }
        } catch (error) {
            console.error('Failed to load tags:', error);
        }
    }

    renderTagFilter() {
        const tagFilter = document.getElementById('tagFilter');
        tagFilter.innerHTML = '<option value="">All Tags</option>';
        
        this.tags.forEach(tag => {
            const option = document.createElement('option');
            option.value = tag;
            option.textContent = tag;
            tagFilter.appendChild(option);
        });
    }

    renderNotes() {
        const container = document.getElementById('notesContainer');
        const emptyState = document.getElementById('emptyState');
        
        if (this.notes.length === 0) {
            container.innerHTML = '';
            emptyState.classList.remove('hidden');
            return;
        }
        
        emptyState.classList.add('hidden');
        container.innerHTML = '';
        
        this.notes.forEach(note => {
            const noteCard = this.createNoteCard(note);
            container.appendChild(noteCard);
        });
    }

    createNoteCard(note) {
        const card = document.createElement('div');
        card.className = 'note-card bg-white rounded-lg shadow-sm p-6 fade-in';
        card.dataset.noteId = note.id;
        
        const tagsHtml = note.tags.map(tag => 
            `<span class="tag inline-block bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full mr-1 mb-1">${this.escapeHtml(tag)}</span>`
        ).join('');
        
        card.innerHTML = `
            <div class="flex justify-between items-start mb-3">
                <h3 class="text-lg font-semibold text-gray-900 flex-1 mr-2">${this.escapeHtml(note.title)}</h3>
                <div class="flex space-x-1">
                    <button onclick="app.editNote('${note.id}')" class="text-blue-600 hover:text-blue-800 p-1">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button onclick="app.deleteNote('${note.id}')" class="text-red-600 hover:text-red-800 p-1">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
            <p class="text-gray-600 mb-3 whitespace-pre-wrap">${this.escapeHtml(note.content)}</p>
            ${tagsHtml ? `<div class="mb-3">${tagsHtml}</div>` : ''}
            <div class="text-xs text-gray-400">
                <i class="fas fa-clock"></i> ${this.formatDate(note.updatedAt)}
            </div>
        `;
        
        return card;
    }

    filterNotes() {
        const searchTerm = document.getElementById('searchInput').value.toLowerCase();
        const selectedTag = document.getElementById('tagFilter').value;
        
        let filteredNotes = this.notes;
        
        if (searchTerm) {
            filteredNotes = filteredNotes.filter(note => 
                note.title.toLowerCase().includes(searchTerm) ||
                note.content.toLowerCase().includes(searchTerm) ||
                note.tags.some(tag => tag.toLowerCase().includes(searchTerm))
            );
        }
        
        if (selectedTag) {
            filteredNotes = filteredNotes.filter(note =>
                note.tags.includes(selectedTag)
            );
        }
        
        const container = document.getElementById('notesContainer');
        container.innerHTML = '';
        
        if (filteredNotes.length === 0) {
            container.innerHTML = '<div class="col-span-full text-center py-8 text-gray-500">No notes found</div>';
            return;
        }
        
        filteredNotes.forEach(note => {
            const noteCard = this.createNoteCard(note);
            container.appendChild(noteCard);
        });
    }

    openNoteModal(noteId = null) {
        const modal = document.getElementById('noteModal');
        const modalTitle = document.getElementById('modalTitle');
        const form = document.getElementById('noteForm');
        
        if (noteId) {
            const note = this.notes.find(n => n.id === noteId);
            if (note) {
                modalTitle.textContent = 'Edit Note';
                document.getElementById('noteId').value = note.id;
                document.getElementById('noteTitle').value = note.title;
                document.getElementById('noteContent').value = note.content;
                document.getElementById('noteTags').value = note.tags.join(', ');
                this.currentEditingId = noteId;
            }
        } else {
            modalTitle.textContent = 'New Note';
            form.reset();
            document.getElementById('noteId').value = '';
            this.currentEditingId = null;
        }
        
        modal.classList.remove('hidden');
        document.getElementById('noteTitle').focus();
    }

    closeNoteModal() {
        const modal = document.getElementById('noteModal');
        modal.classList.add('hidden');
        document.getElementById('noteForm').reset();
        this.currentEditingId = null;
    }

    async saveNote() {
        const title = document.getElementById('noteTitle').value.trim();
        const content = document.getElementById('noteContent').value.trim();
        const tagsInput = document.getElementById('noteTags').value.trim();
        
        if (!title || !content) {
            this.showToast('Title and content are required', 'error');
            return;
        }
        
        const tags = tagsInput ? tagsInput.split(',').map(tag => tag.trim()).filter(tag => tag) : [];
        
        const noteData = { title, content, tags };
        
        try {
            let response;
            
            if (this.currentEditingId) {
                response = await fetch(`/api/notes/${this.currentEditingId}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': this.csrfToken
                    },
                    body: JSON.stringify(noteData)
                });
            } else {
                response = await fetch('/api/notes', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': this.csrfToken
                    },
                    body: JSON.stringify(noteData)
                });
            }
            
            const data = await response.json();
            
            if (data.success) {
                this.showToast(this.currentEditingId ? 'Note updated successfully' : 'Note created successfully', 'success');
                this.closeNoteModal();
                await this.loadNotes();
                await this.loadTags();
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            console.error('Failed to save note:', error);
            this.showToast('Failed to save note', 'error');
        }
    }

    editNote(noteId) {
        this.openNoteModal(noteId);
    }

    async deleteNote(noteId) {
        if (!confirm('Are you sure you want to delete this note?')) {
            return;
        }
        
        try {
            const response = await fetch(`/api/notes/${noteId}`, {
                method: 'DELETE',
                headers: {
                    'X-CSRF-Token': this.csrfToken
                }
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.showToast('Note deleted successfully', 'success');
                await this.loadNotes();
                await this.loadTags();
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            console.error('Failed to delete note:', error);
            this.showToast('Failed to delete note', 'error');
        }
    }

    showToast(message, type = 'info') {
        const toast = document.getElementById('toast');
        const toastMessage = document.getElementById('toastMessage');
        const toastIcon = document.getElementById('toastIcon');
        
        toastMessage.textContent = message;
        
        // Set icon based on type
        const icons = {
            success: '<i class="fas fa-check-circle text-green-500"></i>',
            error: '<i class="fas fa-exclamation-circle text-red-500"></i>',
            info: '<i class="fas fa-info-circle text-blue-500"></i>'
        };
        
        toastIcon.innerHTML = icons[type] || icons.info;
        
        toast.classList.remove('hidden');
        
        setTimeout(() => {
            toast.classList.add('hidden');
        }, 3000);
    }

    hideLoading() {
        document.getElementById('loadingState').classList.add('hidden');
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    formatDate(dateString) {
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);
        
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
        if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
        if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
        
        return date.toLocaleDateString();
    }
}

// Initialize the app
const app = new SecureNotesApp();
