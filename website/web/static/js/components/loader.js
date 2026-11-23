"use strict";
// Lookyloo eyes loading indicator for JavaScript. Same markup as the loader()
// Jinja macro (templates/macros/loader.html): keep both in sync.
// Doc: doc/ui/loader.md

// Returns the HTML of the loader. The label is escaped (set through textContent).
function lkLoader(label = 'Loading', size = 'md', showLabel = false) {
    const wrapper = document.createElement('span');
    wrapper.className = `lk-loader lk-loader-${['sm', 'md', 'lg'].includes(size) ? size : 'md'}`;
    wrapper.setAttribute('role', 'status');
    wrapper.innerHTML = `<svg class="lk-loader-eyes" viewBox="0 0 64 30" aria-hidden="true" focusable="false">
    <g class="lk-eye"><circle class="lk-eye-ring" cx="15" cy="15" r="11.5" pathLength="100"></circle><circle class="lk-eye-pupil" cx="17.5" cy="17.5" r="4.6"></circle></g>
    <g class="lk-eye"><circle class="lk-eye-ring" cx="49" cy="15" r="11.5" pathLength="100"></circle><circle class="lk-eye-pupil" cx="51.5" cy="17.5" r="4.6"></circle></g>
  </svg>`;
    const text = document.createElement('span');
    text.className = showLabel ? 'lk-loader-label' : 'visually-hidden';
    text.textContent = label;
    wrapper.appendChild(text);
    return wrapper.outerHTML;
}

// Forms with data-lk-loading="Label": on submit, the submit button shows the eyes and is disabled.
document.addEventListener('submit', event => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.dataset.lkLoading) {
        return;
    }
    const button = event.submitter || form.querySelector('[type="submit"]');
    if (button) {
        button.dataset.lkOriginal = button.innerHTML;
        button.classList.add('lk-btn-loading');
        button.innerHTML = lkLoader(form.dataset.lkLoading, 'sm', true);
        // Disabled after the submission has been built, so the button value is still sent
        setTimeout(() => { button.disabled = true; }, 0);
    }
});

// Back button (page restored from the browser cache): give the buttons back their content
window.addEventListener('pageshow', event => {
    if (!event.persisted) {
        return;
    }
    document.querySelectorAll('.lk-btn-loading').forEach(button => {
        button.innerHTML = button.dataset.lkOriginal || button.innerHTML;
        button.classList.remove('lk-btn-loading');
        button.disabled = false;
    });
});
