// Wrapper for async functions to avoid try-catch blocks in route handlers
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

module.exports = {
  asyncHandler,
};
