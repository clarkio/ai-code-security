const mongoose = require('mongoose');

const noteSchema = new mongoose.Schema({
    title: {
        type: String,
        required: [true, 'Note title cannot be blank.'],
        trim: true,
        maxlength: [100, 'Title cannot be more than 100 characters']
    },
    content: {
        type: String,
        required: [true, 'Note content cannot be blank.'],
        trim: true,
        maxlength: [5000, 'Content cannot be more than 5000 characters']
    }
}, {
    timestamps: true // Automatically adds createdAt and updatedAt fields
});

// Basic input sanitization can be added here if needed, though
// express-validator in routes is the primary defense.
// Example (though often better handled before saving):
// noteSchema.pre('save', function(next) {
//   if (this.title) this.title = sanitizeHtml(this.title, { allowedTags: [], allowedAttributes: {} });
//   if (this.content) this.content = sanitizeHtml(this.content, { allowedTags: [], allowedAttributes: {} });
//   next();
// });

module.exports = mongoose.model('Note', noteSchema); 