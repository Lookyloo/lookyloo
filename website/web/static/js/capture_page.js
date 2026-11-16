"use strict";
// Capture page (tree/tree.html). Doc: doc/ui/tree.md
// - The top block (site header, capture bar) stays at the top of the window,
//   even when the tree is scrolled sideways.
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

    // The top block is fixed (css/components/capture-bar.css): the page starts under it
    const measure = () => {
        document.documentElement.style.setProperty('--lk-capture-top-height', `${top.offsetHeight}px`);
    };
    new ResizeObserver(measure).observe(top);
    measure();

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
// - Pointer events + pointer capture: the drag goes on, and ends, even when the
//   mouse leaves the window.
// - No text selection and no native drag of the images (screenshot thumbnail):
//   both started on the press and fought with the scroll.
// - A smooth glide still running (opening of the page, Center) is stopped by
//   the press, otherwise it pulled the page away from the mouse.
(() => {
    const area = document.getElementById('tree_svg');
    if (!area) {
        return;
    }
    const THRESHOLD = 4;   // pixels before a press becomes a drag
    // Glow on the side(s) of the window where the drag reached the limit (css/tree.css)
    const edge = document.createElement('div');
    edge.className = 'lk-tree-edge';
    edge.setAttribute('aria-hidden', 'true');
    document.body.appendChild(edge);
    let start = null;
    let dragged = false;

    const scrollNow = (left, top) => {
        // instant: Bootstrap makes the page scroll smooth, it would lag behind the mouse
        window.scrollTo({left: left, top: top, behavior: 'instant'});
    };

    const stop = () => {
        if (!start) {
            return;
        }
        if (area.hasPointerCapture(start.id)) {
            area.releasePointerCapture(start.id);
        }
        start = null;
        area.classList.remove('is-dragging');
        edge.classList.remove('is-left', 'is-right', 'is-top', 'is-bottom');
        // Only the click ending the drag is swallowed (it fires right after the
        // release), not the next click on a node or a button of the tree controls
        if (dragged) {
            setTimeout(() => { dragged = false; }, 0);
        }
    };

    area.addEventListener('pointerdown', (event) => {
        if (event.pointerType !== 'mouse' || event.button !== 0
            || event.target.closest('a, button, input, textarea, select, .dropdown-menu, #legend, #tree-zoom, #lk-side-panel')) {
            return;
        }
        // No text selection, no native drag; stops a smooth glide in progress
        event.preventDefault();
        scrollNow(window.scrollX, window.scrollY);
        start = {id: event.pointerId, x: event.clientX, y: event.clientY, sx: window.scrollX, sy: window.scrollY};
        dragged = false;
    });

    area.addEventListener('pointermove', (event) => {
        if (!start || event.pointerId !== start.id) {
            return;
        }
        const dx = event.clientX - start.x;
        const dy = event.clientY - start.y;
        if (!dragged) {
            if (Math.hypot(dx, dy) < THRESHOLD) {
                return;
            }
            dragged = true;
            area.classList.add('is-dragging');
            area.setPointerCapture(start.id);
        }
        const left = start.sx - dx;
        const top = start.sy - dy;
        scrollNow(left, top);
        // Past the edge of the free room: that side of the window glows blue
        const root = document.documentElement;
        edge.classList.toggle('is-left', left < 0);
        edge.classList.toggle('is-right', left > root.scrollWidth - window.innerWidth);
        edge.classList.toggle('is-top', top < 0);
        edge.classList.toggle('is-bottom', top > root.scrollHeight - window.innerHeight);
    });

    area.addEventListener('pointerup', stop);
    area.addEventListener('pointercancel', stop);
    area.addEventListener('lostpointercapture', stop);
    window.addEventListener('blur', stop);

    // Images and links of the tree are never dragged by the browser
    area.addEventListener('dragstart', (event) => event.preventDefault());

    area.addEventListener('click', (event) => {
        if (dragged) {
            event.stopPropagation();
            event.preventDefault();
            dragged = false;
        }
    }, true);
})();
