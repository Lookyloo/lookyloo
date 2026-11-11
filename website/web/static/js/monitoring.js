"use strict";
// Admin monitoring page (admin/monitoring.html): the folded sections
// (<details data-lk-mon-url>) request their body each time they are opened,
// so nothing is read from the backend for a section nobody looks at.
// The body is an HTML fragment rendered (and escaped) by Flask.
// Doc: doc/ui/monitoring.md

document.querySelectorAll('details[data-lk-mon-url]').forEach(section => {
    let controller = null;
    section.addEventListener('toggle', async () => {
        if (!section.open) {
            if (controller) {
                controller.abort();
            }
            return;
        }
        const body = section.querySelector('.lk-mon-panel-body');
        body.replaceChildren(lkLoader('Loading', 'md', true));
        controller = new AbortController();
        try {
            const response = await fetch(section.dataset.lkMonUrl, {
                credentials: 'same-origin', signal: controller.signal,
            });
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            body.innerHTML = await response.text();
        } catch (error) {
            if (error.name === 'AbortError') {
                return;
            }
            const message = document.createElement('p');
            message.className = 'lk-mon-error';
            message.textContent = `Unable to load this section (${error.message}). Close and open it again to retry.`;
            body.replaceChildren(message);
        }
    });
});
