"use strict";
// Search page (templates/home/search.html): the server searches one field only
// (the first one filled, website/web/__init__.py search()). As soon as a field is
// filled, the others are disabled and greyed out; emptied, they come back.
// Doc: doc/ui/search.md
(() => {
    const form = document.querySelector('form.lk-search');
    if (!form) return;
    const fields = [...form.querySelectorAll('.lk-search-field')];
    const inputOf = field => field.querySelector('input');
    const note = form.querySelector('.lk-search-note span');
    const default_note = note ? [...note.childNodes].map(n => n.cloneNode(true)) : [];

    const refresh = () => {
        const filled = fields.find(field => inputOf(field).value.trim() !== '');
        fields.forEach(field => {
            const off = Boolean(filled) && field !== filled;
            inputOf(field).disabled = off;
            field.classList.toggle('is-disabled', off);
            field.classList.toggle('is-chosen', field === filled);
        });
        if (!note) return;
        if (filled) {
            const label = filled.querySelector('label').textContent.trim();
            note.textContent = `Searching by ${label}. Empty this field to search by another one.`;
        } else {
            note.replaceChildren(...default_note.map(n => n.cloneNode(true)));
        }
    };
    form.addEventListener('input', refresh);
    form.addEventListener('change', refresh);
    // A greyed field shows why: a click on it says which field to empty
    fields.forEach(field => field.addEventListener('click', () => {
        if (field.classList.contains('is-disabled')) form.querySelector('.is-chosen input')?.focus();
    }));
    refresh();   // values kept after an error (back_to_form)
})();
