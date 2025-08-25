'use strict';

const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
    {
        email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
        passwordHash: { type: String, required: true }
    },
    {
        timestamps: true,
        versionKey: false
    }
);

const User = mongoose.model('User', userSchema);
module.exports = { User };


