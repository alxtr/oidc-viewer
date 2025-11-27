class IconToggle {
    static TOGGLE_TIMEOUT_MS = 1000;

    constructor(selector) {
        this.selector = selector;
        this.buttonTimeouts = new Map();
        this.init();
    }

    init() {
        const toggleButtons = document.querySelectorAll(this.selector);
        toggleButtons.forEach(button => {
            this.setupButton(button);
        });
    }

    setupButton(button) {
        button.setAttribute('data-original-classes', button.className);
        const defaultIcon = button.getAttribute('data-icon-default');
        button.innerHTML = `<i class='bi ${defaultIcon}'></i>`;
    }

    trigger(button) {
        clearTimeout(this.buttonTimeouts.get(button));

        const toggledIcon = button.getAttribute('data-icon-toggled');
        button.innerHTML = `<i class='bi ${toggledIcon}'></i>`;

        // Temporarily replace original color class with success class
        const originalBtnClasses = button.dataset.originalClasses.split(' ').filter(c => c.startsWith('btn-'));
        button.classList.remove(...originalBtnClasses);
        button.classList.add('btn-outline-success');

        const timeoutId = setTimeout(() => {
            const defaultIcon = button.getAttribute('data-icon-default');
            button.innerHTML = `<i class='bi ${defaultIcon}'></i>`;
            button.classList.remove('btn-outline-success');
            button.classList.add(...originalBtnClasses);

            this.buttonTimeouts.delete(button);
        }, IconToggle.TOGGLE_TIMEOUT_MS);

        this.buttonTimeouts.set(button, timeoutId);
    }
}
