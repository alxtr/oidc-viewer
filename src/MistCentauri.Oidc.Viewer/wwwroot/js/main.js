document.addEventListener('DOMContentLoaded', () => {
    // Set bootstrap theme
    document.documentElement.setAttribute('data-bs-theme', (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));

    // Init clipboard buttons
    const toggle = new IconToggle('[mc-toggle]');
    const clipboard = new ClipboardJS('[mc-toggle]');

    clipboard.on('success', (e) => {
        toggle.trigger(e.trigger);
        e.clearSelection();
    });

    clipboard.on('error', (e) => {
        console.error('Clipboard copy failed:', e.action);
    });
});
