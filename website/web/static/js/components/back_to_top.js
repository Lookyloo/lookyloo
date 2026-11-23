"use strict";
// "Back to top" button of layouts/page.html: shown after scrolling down a bit.
// Doc: doc/ui/back-to-top.md

document.addEventListener('DOMContentLoaded', () => {
    const button = document.getElementById('lk-back-to-top');
    if (!button) {
        return;
    }
    const threshold = 400;
    let ticking = false;
    const update = () => {
        const visible = window.scrollY > threshold;
        button.classList.toggle('is-visible', visible);
        // Not reachable with the keyboard while hidden
        button.tabIndex = visible ? 0 : -1;
        ticking = false;
    };
    window.addEventListener('scroll', () => {
        if (!ticking) {
            ticking = true;
            window.requestAnimationFrame(update);
        }
    }, { passive: true });
    update();

    button.addEventListener('click', () => {
        const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        window.scrollTo({ top: 0, behavior: reduce ? 'auto' : 'smooth' });
        // Keyboard users continue from the top of the content
        document.getElementById('content')?.focus({ preventScroll: true });
    });
});
