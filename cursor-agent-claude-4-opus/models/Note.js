const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');
const DOMPurify = require('isomorphic-dompurify');

const Note = sequelize.define('Note', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
    allowNull: false
  },
  title: {
    type: DataTypes.STRING(255),
    allowNull: false,
    validate: {
      notEmpty: true,
      len: [1, 255]
    },
    set(value) {
      // Sanitize title to prevent XSS
      this.setDataValue('title', DOMPurify.sanitize(value, { ALLOWED_TAGS: [] }));
    }
  },
  content: {
    type: DataTypes.TEXT,
    allowNull: false,
    validate: {
      notEmpty: true,
      len: [1, 50000] // Limit content length
    },
    set(value) {
      // Sanitize content to prevent XSS, allowing basic formatting
      this.setDataValue('content', DOMPurify.sanitize(value, {
        ALLOWED_TAGS: ['b', 'i', 'u', 'strong', 'em', 'p', 'br', 'ul', 'ol', 'li'],
        ALLOWED_ATTR: []
      }));
    }
  },
  user_id: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'users',
      key: 'id'
    }
  },
  is_public: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false
  },
  is_encrypted: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false
  },
  tags: {
    type: DataTypes.JSON,
    defaultValue: [],
    validate: {
      isArray(value) {
        if (!Array.isArray(value)) {
          throw new Error('Tags must be an array');
        }
        if (value.length > 10) {
          throw new Error('Maximum 10 tags allowed');
        }
        value.forEach(tag => {
          if (typeof tag !== 'string' || tag.length > 50) {
            throw new Error('Each tag must be a string with max 50 characters');
          }
        });
      }
    },
    set(value) {
      // Sanitize each tag
      if (Array.isArray(value)) {
        const sanitizedTags = value.map(tag => 
          DOMPurify.sanitize(tag, { ALLOWED_TAGS: [] })
        );
        this.setDataValue('tags', sanitizedTags);
      }
    }
  },
  view_count: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    allowNull: false,
    validate: {
      min: 0
    }
  },
  last_modified_by: {
    type: DataTypes.UUID,
    allowNull: true
  }
}, {
  tableName: 'notes',
  indexes: [
    {
      fields: ['user_id']
    },
    {
      fields: ['is_public']
    },
    {
      fields: ['created_at']
    }
  ]
});

// Class methods for secure queries
Note.findByUser = function(userId, options = {}) {
  return this.findAll({
    where: {
      user_id: userId,
      ...options.where
    },
    order: [['created_at', 'DESC']],
    ...options
  });
};

Note.findPublic = function(options = {}) {
  return this.findAll({
    where: {
      is_public: true,
      ...options.where
    },
    order: [['created_at', 'DESC']],
    ...options
  });
};

module.exports = Note;