'use strict';

const mongoose = require('mongoose');

const noteSchema = new mongoose.Schema(
    {
        userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
        title: { type: String, required: true, trim: true, maxlength: 200 },
        body: { type: String, required: true, trim: true, maxlength: 5000 }
    },
    {
        timestamps: true,
        versionKey: false
    }
);

noteSchema.index({ userId: 1, createdAt: -1 });

const Note = mongoose.model('Note', noteSchema);
module.exports = { Note };


