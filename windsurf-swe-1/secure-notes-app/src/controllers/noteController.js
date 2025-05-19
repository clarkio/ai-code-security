const Note = require('../models/Note');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');

// Helper function to filter allowed fields
const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach((el) => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

// Create a new note
exports.createNote = catchAsync(async (req, res, next) => {
  // 1) Filtered out unwanted fields that are not allowed to be set
  const filteredBody = filterObj(
    req.body,
    'title',
    'content',
    'isPinned',
    'tags',
    'color'
  );

  // 2) Set the user ID from the request
  filteredBody.user = req.user.id;

  // 3) Create the note
  const newNote = await Note.create(filteredBody);

  // 4) Send response
  res.status(201).json({
    status: 'success',
    data: {
      note: newNote,
    },
  });
});

// Get all notes for the logged-in user
exports.getAllNotes = catchAsync(async (req, res, next) => {
  // 1) Filtering
  const queryObj = { ...req.query, user: req.user.id };
  const excludedFields = ['page', 'sort', 'limit', 'fields'];
  excludedFields.forEach((el) => delete queryObj[el]);

  // 2) Advanced filtering
  let queryStr = JSON.stringify(queryObj);
  queryStr = queryStr.replace(/\b(gte|gt|lte|lt)\b/g, (match) => `$${match}`);

  let query = Note.find(JSON.parse(queryStr));

  // 3) Sorting
  if (req.query.sort) {
    const sortBy = req.query.sort.split(',').join(' ');
    query = query.sort(sortBy);
  } else {
    query = query.sort('-isPinned -updatedAt');
  }

  // 4) Field limiting
  if (req.query.fields) {
    const fields = req.query.fields.split(',').join(' ');
    query = query.select(fields);
  } else {
    query = query.select('-__v');
  }

  // 5) Pagination
  const page = req.query.page * 1 || 1;
  const limit = req.query.limit * 1 || 100;
  const skip = (page - 1) * limit;

  const total = await Note.countDocuments(JSON.parse(queryStr));
  
  if (req.query.page) {
    if (skip >= total) {
      return next(new AppError('This page does not exist', 404));
    }
  }

  query = query.skip(skip).limit(limit);

  // 6) Execute query
  const notes = await query;

  // 7) Send response
  res.status(200).json({
    status: 'success',
    results: notes.length,
    total,
    totalPages: Math.ceil(total / limit),
    data: {
      notes,
    },
  });
});

// Get a single note
exports.getNote = catchAsync(async (req, res, next) => {
  const note = await Note.findOne({ _id: req.params.id, user: req.user.id });

  if (!note) {
    return next(new AppError('No note found with that ID', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      note,
    },
  });
});

// Update a note
exports.updateNote = catchAsync(async (req, res, next) => {
  // 1) Filtered out unwanted fields that are not allowed to be updated
  const filteredBody = filterObj(
    req.body,
    'title',
    'content',
    'isPinned',
    'tags',
    'color',
    'isArchived'
  );

  // 2) Update note document
  const updatedNote = await Note.findOneAndUpdate(
    { _id: req.params.id, user: req.user.id },
    filteredBody,
    {
      new: true,
      runValidators: true,
    }
  );

  if (!updatedNote) {
    return next(new AppError('No note found with that ID', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      note: updatedNote,
    },
  });
});

// Delete a note
exports.deleteNote = catchAsync(async (req, res, next) => {
  const note = await Note.findOneAndDelete({
    _id: req.params.id,
    user: req.user.id,
  });

  if (!note) {
    return next(new AppError('No note found with that ID', 404));
  }

  res.status(204).json({
    status: 'success',
    data: null,
  });
});

// Search notes
exports.searchNotes = catchAsync(async (req, res, next) => {
  const { q: searchQuery, page = 1, limit = 10 } = req.query;

  if (!searchQuery) {
    return next(new AppError('Please provide a search query', 400));
  }

  const result = await Note.search(
    req.user.id,
    searchQuery,
    { page: parseInt(page), limit: parseInt(limit) }
  );

  res.status(200).json({
    status: 'success',
    ...result,
  });
});

// Get note statistics
exports.getNoteStats = catchAsync(async (req, res, next) => {
  const stats = await Note.aggregate([
    {
      $match: { user: req.user._id }
    },
    {
      $group: {
        _id: null,
        totalNotes: { $sum: 1 },
        pinnedNotes: {
          $sum: { $cond: [{ $eq: ['$isPinned', true] }, 1, 0] },
        },
        archivedNotes: {
          $sum: { $cond: [{ $eq: ['$isArchived', true] }, 1, 0] },
        },
        avgContentLength: { $avg: { $strLenCP: '$content' } },
        minContentLength: { $min: { $strLenCP: '$content' } },
        maxContentLength: { $max: { $strLenCP: '$content' } },
      },
    },
    {
      $project: {
        _id: 0,
        totalNotes: 1,
        pinnedNotes: 1,
        archivedNotes: 1,
        activeNotes: { $subtract: ['$totalNotes', '$archivedNotes'] },
        avgContentLength: { $round: ['$avgContentLength', 0] },
        minContentLength: 1,
        maxContentLength: 1,
      },
    },
  ]);

  // Get tag statistics
  const tagStats = await Note.aggregate([
    { $match: { user: req.user._id } },
    { $unwind: '$tags' },
    {
      $group: {
        _id: '$tags',
        count: { $sum: 1 },
      },
    },
    { $sort: { count: -1 } },
    { $limit: 10 },
  ]);

  res.status(200).json({
    status: 'success',
    data: {
      stats: stats[0] || {
        totalNotes: 0,
        pinnedNotes: 0,
        archivedNotes: 0,
        activeNotes: 0,
        avgContentLength: 0,
        minContentLength: 0,
        maxContentLength: 0,
      },
      tagStats,
    },
  });
});
