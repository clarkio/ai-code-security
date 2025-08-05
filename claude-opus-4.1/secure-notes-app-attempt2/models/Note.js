const mongoose = require("mongoose");
const xss = require("xss");

const noteSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, "Title is required"],
      trim: true,
      maxlength: [100, "Title cannot exceed 100 characters"],
    },
    content: {
      type: String,
      required: [true, "Content is required"],
      maxlength: [5000, "Content cannot exceed 5000 characters"],
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    tags: [
      {
        type: String,
        trim: true,
        maxlength: 20,
      },
    ],
    isDeleted: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

// Sanitize input before saving
noteSchema.pre("save", function (next) {
  this.title = xss(this.title);
  this.content = xss(this.content);
  if (this.tags && this.tags.length > 0) {
    this.tags = this.tags.map((tag) => xss(tag)).slice(0, 10); // Max 10 tags
  }
  next();
});

// Add compound index for efficient queries
noteSchema.index({ user: 1, isDeleted: 1, createdAt: -1 });

module.exports = mongoose.model("Note", noteSchema);
