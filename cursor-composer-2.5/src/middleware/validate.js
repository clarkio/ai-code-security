export function validateBody(schema, { redirectTo = '/' } = {}) {
  return (req, res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      const message = result.error.errors.map((e) => e.message).join('. ');
      req.session.flash = { type: 'error', message };
      return res.redirect(redirectTo);
    }
    req.validated = result.data;
    next();
  };
}

export function validateParams(schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.params);
    if (!result.success) {
      return res.status(404).render('error', {
        title: 'Not found',
        message: 'The requested resource was not found.',
        statusCode: 404,
      });
    }
    req.validatedParams = result.data.id;
    next();
  };
}
