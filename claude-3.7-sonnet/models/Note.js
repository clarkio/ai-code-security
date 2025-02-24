const mongoose = require('mongoose');

const NoteSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Please add a title'],
    trim: true,
    maxlength: [100, 'Title cannot be more than 100 characters']
  },
  content: {
    type: String,
    required: [true, 'Please add content'],
    trim: true,
    maxlength: [5000, 'Content cannot be more than 5000 characters']
  },
  user: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Set updatedAt on save
NoteSchema.pre('save', function(next) {
  if (this.isModified('title') || this.isModified('content')) {
    this.updatedAt = Date.now();
  }
  next();
});

module.exports = mongoose.model('Note', NoteSchema);