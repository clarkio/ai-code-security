const mongoose = require('mongoose');
const validator = require('validator');

const noteSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, 'A note must have a title'],
      trim: true,
      maxlength: [100, 'A note title must have less or equal than 100 characters'],
      minlength: [1, 'A note title must have more or equal than 1 character'],
    },
    content: {
      type: String,
      required: [true, 'A note must have content'],
      trim: true,
      maxlength: [10000, 'A note content must have less or equal than 10000 characters'],
      minlength: [1, 'A note content must have more or equal than 1 character'],
    },
    user: {
      type: mongoose.Schema.ObjectId,
      ref: 'User',
      required: [true, 'Note must belong to a user'],
    },
    isPinned: {
      type: Boolean,
      default: false,
    },
    tags: [
      {
        type: String,
        trim: true,
        maxlength: [20, 'A tag must have less or equal than 20 characters'],
      },
    ],
    isArchived: {
      type: Boolean,
      default: false,
    },
    color: {
      type: String,
      default: '#ffffff',
      validate: {
        validator: function (value) {
          // Simple hex color validation
          return /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/.test(value);
        },
        message: 'Color must be a valid hex color code',
      },
    },
    lastEdited: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Indexes for better query performance
noteSchema.index({ user: 1 });
noteSchema.index({ user: 1, isArchived: 1 });
noteSchema.index({ user: 1, isPinned: -1, updatedAt: -1 });
noteSchema.index({ user: 1, tags: 1 });
noteSchema.index({ title: 'text', content: 'text' });

// Document middleware to update lastEdited timestamp
noteSchema.pre('save', function (next) {
  if (this.isModified('title') || this.isModified('content') || this.isModified('tags')) {
    this.lastEdited = Date.now();
  }
  next();
});

// Query middleware to populate user data
noteSchema.pre(/^find/, function (next) {
  this.populate({
    path: 'user',
    select: 'name email',
  });
  next();
});

// Static method for text search
noteSchema.statics.search = async function (userId, query, options = {}) {
  const { limit = 10, page = 1 } = options;
  const skip = (page - 1) * limit;

  const searchQuery = {
    $and: [
      { user: userId },
      {
        $or: [
          { title: { $regex: query, $options: 'i' } },
          { content: { $regex: query, $options: 'i' } },
          { tags: { $in: [new RegExp(query, 'i')] } },
        ],
      },
    ],
  };

  const [notes, total] = await Promise.all([
    this.find(searchQuery)
      .sort({ isPinned: -1, updatedAt: -1 })
      .skip(skip)
      .limit(limit),
    this.countDocuments(searchQuery),
  ]);

  return {
    results: notes,
    page,
    limit,
    totalPages: Math.ceil(total / limit),
    totalResults: total,
  };
};

const Note = mongoose.model('Note', noteSchema);

module.exports = Note;
