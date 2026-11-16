"use strict";
// Capture page (tree/tree.html). Doc: doc/ui/tree.md
// - The top block (site header, capture bar) stays at the top of the page.
// - The capture bar can be folded to one line; the choice is remembered.

(() => {
    const top = document.getElementById('capture_top');
    const bar = document.getElementById('menu_vertical');
    const fold = document.getElementById('capture_fold');
    if (!top || !bar || !fold) {
        return;
    }
    const KEY = 'lk-capture-bar-folded';

    const setFolded = (folded) => {
        bar.classList.toggle('is-folded', folded);
        fold.setAttribute('aria-expanded', folded ? 'false' : 'true');
        const label = folded ? 'Unfold the capture bar' : 'Fold the capture bar';
        fold.title = label;
        fold.querySelector('.visually-hidden').textContent = label;
    };
    let folded = false;
    try {
        folded = localStorage.getItem(KEY) === '1';
    } catch (e) { /* storage unavailable: unfolded */ }
    setFolded(folded);

    fold.addEventListener('click', () => {
        folded = !bar.classList.contains('is-folded');
        setFolded(folded);
        try {
            localStorage.setItem(KEY, folded ? '1' : '0');
        } catch (e) { /* not remembered */ }
    });
})();
