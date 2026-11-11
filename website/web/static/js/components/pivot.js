"use strict";
// Pivot pages (templates/investigate/*, macros/investigate.html): the total
// number of captures next to the title ([data-lk-count]); when the captures
// table comes back empty, hide it and show the message with the links to
// Search and to the list of the captures (.lk-pivot-empty). Works on the
// standalone pages and in the capture modals (delegated on document).
// Doc: doc/ui/pivot-pages.md
$(document).on('draw.dt', '.lk-pivot-captures table', function (e, settings) {
    const section = this.closest('.lk-pivot-captures');
    if (!section) return;
    const total = new $.fn.dataTable.Api(settings).page.info().recordsTotal;
    const empty = total === 0;
    // Total next to the title: how many captures have this value
    const count = section.querySelector('[data-lk-count]');
    if (count) {
        count.hidden = empty;
        count.textContent = total.toLocaleString('en');
        count.title = `${total} capture${total > 1 ? 's' : ''}`;
    }
    const note = section.querySelector('.lk-pivot-empty');
    const wrapper = section.querySelector('.lk-capture-list');
    if (note) note.hidden = !empty;
    if (wrapper) wrapper.hidden = empty;
});

// Image of a pivot (favicon) shown in large: click on [data-lk-zoom] opens a
// dialog with the same image (no new request: same src), closed by a click,
// the close button or Escape.
document.addEventListener('click', (event) => {
    const button = event.target.closest('[data-lk-zoom]');
    if (!button) return;
    const source = button.querySelector('img');
    if (!source) return;
    const dialog = document.createElement('dialog');
    dialog.className = 'lk-zoom-dialog';
    const image = document.createElement('img');
    image.src = source.src;
    image.alt = 'Image in large';
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'btn-close';
    close.setAttribute('aria-label', 'Close');
    dialog.append(close, image);
    dialog.addEventListener('click', () => dialog.close());
    dialog.addEventListener('close', () => dialog.remove());
    document.body.appendChild(dialog);
    dialog.showModal();
});
