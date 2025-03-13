const mongoose = require('mongoose');
const { Schema } = mongoose;

const noteSchema = new Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
      maxlength: [200, 'Title cannot exceed 200 characters'],
    },
    content: {
      type: String,
      required: true,
      trim: true,
      maxlength: [10000, 'Content cannot exceed 10000 characters'],
    },
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
  },
  {
    timestamps: true,
  }
);

// Create compound index on userId and _id for efficient queries
noteSchema.index({ userId: 1, _id: 1 });

// Define methods for sanitization and validation
noteSchema.methods.toJSON = function() {
  const note = this.toObject();
  return {
    id: note._id,
    title: note.title,
    content: note.content,
    createdAt: note.createdAt,
    updatedAt: note.updatedAt,
  };
};

module.exports = mongoose.model('Note', noteSchema);