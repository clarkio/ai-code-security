document.querySelectorAll('form[data-confirm-delete]').forEach((form) => {
  form.addEventListener('submit', (event) => {
    if (!window.confirm('Delete this note?')) {
      event.preventDefault();
    }
  });
});
