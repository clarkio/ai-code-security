class NotesController {
    constructor(noteModel) {
        this.noteModel = noteModel;
    }

    async createNote(req, res) {
        try {
            const { title, content } = req.body;
            const newNote = await this.noteModel.create({ title, content, userId: req.user.id });
            res.status(201).json(newNote);
        } catch (error) {
            res.status(500).json({ message: 'Error creating note', error: error.message });
        }
    }

    async getNotes(req, res) {
        try {
            const notes = await this.noteModel.find({ userId: req.user.id });
            res.status(200).json(notes);
        } catch (error) {
            res.status(500).json({ message: 'Error fetching notes', error: error.message });
        }
    }

    async updateNote(req, res) {
        try {
            const { id } = req.params;
            const { title, content } = req.body;
            const updatedNote = await this.noteModel.findByIdAndUpdate(id, { title, content }, { new: true });
            if (!updatedNote) {
                return res.status(404).json({ message: 'Note not found' });
            }
            res.status(200).json(updatedNote);
        } catch (error) {
            res.status(500).json({ message: 'Error updating note', error: error.message });
        }
    }

    async deleteNote(req, res) {
        try {
            const { id } = req.params;
            const deletedNote = await this.noteModel.findByIdAndDelete(id);
            if (!deletedNote) {
                return res.status(404).json({ message: 'Note not found' });
            }
            res.status(204).send();
        } catch (error) {
            res.status(500).json({ message: 'Error deleting note', error: error.message });
        }
    }
}

export default NotesController;