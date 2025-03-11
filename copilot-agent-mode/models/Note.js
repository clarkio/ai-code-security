const mongoose = require("mongoose");

const noteSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, "A note must have a title"],
      trim: true,
      maxlength: [100, "A note title must have less than 100 characters"],
    },
    content: {
      type: String,
      required: [true, "A note must have content"],
      trim: true,
      maxlength: [10000, "A note must have less than 10,000 characters"],
    },
    user: {
      type: mongoose.Schema.ObjectId,
      ref: "User",
      required: [true, "A note must belong to a user"],
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
    updatedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Index for faster queries by user
noteSchema.index({ user: 1, createdAt: -1 });

// Middleware to update the 'updatedAt' field on save
noteSchema.pre("save", function (next) {
  if (!this.isNew) {
    this.updatedAt = Date.now();
  }
  next();
});

// Middleware to update the 'updatedAt' field on update
noteSchema.pre(["updateOne", "findOneAndUpdate"], function (next) {
  this.set({ updatedAt: Date.now() });
  next();
});

const Note = mongoose.model("Note", noteSchema);

module.exports = Note;
