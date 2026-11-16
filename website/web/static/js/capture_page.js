"use strict";
// Capture page (tree/tree.html). Doc: doc/ui/tree.md
// - The top block (site header, capture bar) stays at the top of the page.
// - The capture bar can be folded to one line; the choice is remembered.
// - The tree can be dragged with the mouse to move around it.

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

// Drag the tree with the mouse: press anywhere on the tree and move to scroll
// the page. A press without movement stays a normal click (node, icons, hostname
// pop-up); after a drag the click is swallowed so nothing opens by accident.
(() => {
    const area = document.getElementById('tree_svg');
    if (!area) {
        return;
    }
    const THRESHOLD = 4;   // pixels before a press becomes a drag
    let start = null;
    let dragged = false;

    area.addEventListener('mousedown', (event) => {
        if (event.button !== 0 || event.target.closest('a, button, input, textarea, select, #legend')) {
            return;
        }
        start = {x: event.clientX, y: event.clientY, sx: window.scrollX, sy: window.scrollY};
        dragged = false;
    });
    window.addEventListener('mousemove', (event) => {
        if (!start) {
            return;
        }
        const dx = event.clientX - start.x;
        const dy = event.clientY - start.y;
        if (!dragged && Math.hypot(dx, dy) < THRESHOLD) {
            return;
        }
        dragged = true;
        area.classList.add('is-dragging');
        event.preventDefault();   // no text selection
        // instant: Bootstrap makes the page scroll smooth, it would lag behind the mouse
        window.scrollTo({left: start.sx - dx, top: start.sy - dy, behavior: 'instant'});
    });
    window.addEventListener('mouseup', () => {
        start = null;
        area.classList.remove('is-dragging');
    });
    area.addEventListener('click', (event) => {
        if (dragged) {
            event.stopPropagation();
            event.preventDefault();
            dragged = false;
        }
    }, true);
})();
