const request = require('supertest');
const app = require('../src/app'); // Adjust the path as necessary
const Note = require('../src/models/note');

describe('Notes API', () => {
    beforeEach(async () => {
        await Note.deleteMany({});
    });

    it('should create a new note', async () => {
        const res = await request(app)
            .post('/api/notes')
            .send({
                title: 'Test Note',
                content: 'This is a test note.'
            });

        expect(res.statusCode).toEqual(201);
        expect(res.body).toHaveProperty('_id');
        expect(res.body.title).toBe('Test Note');
    });

    it('should update an existing note', async () => {
        const note = new Note({
            title: 'Old Note',
            content: 'This is an old note.'
        });
        await note.save();

        const res = await request(app)
            .put(`/api/notes/${note._id}`)
            .send({
                title: 'Updated Note',
                content: 'This is an updated note.'
            });

        expect(res.statusCode).toEqual(200);
        expect(res.body.title).toBe('Updated Note');
    });

    it('should delete a note', async () => {
        const note = new Note({
            title: 'Note to be deleted',
            content: 'This note will be deleted.'
        });
        await note.save();

        const res = await request(app)
            .delete(`/api/notes/${note._id}`);

        expect(res.statusCode).toEqual(204);
    });

    it('should return 404 for a non-existing note', async () => {
        const res = await request(app)
            .get('/api/notes/60d21b4667d0d8992e610c85'); // Example non-existing ID

        expect(res.statusCode).toEqual(404);
    });
});