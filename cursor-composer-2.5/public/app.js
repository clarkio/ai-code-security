document.querySelectorAll('[data-confirm]').forEach((button) => {
  const form = button.closest('form');
  if (!form) return;

  form.addEventListener('submit', (event) => {
    const message = button.getAttribute('data-confirm');
    if (message && !window.confirm(message)) {
      event.preventDefault();
    }
  });
});
