"use strict";
// Loading page of a capture (tree/tree_wait.html): reloads the capture every 10
// seconds until the tree is ready (the server then shows it), with the seconds
// left shown in the "Check now" button. While a tour is open
// (js/components/tour.js, body.lk-tour-running) it waits, and reloads once the
// tour is over. Doc: doc/ui/loader.md
(() => {
    const section = document.querySelector('[data-lk-reload]');
    if (!section) return;
    const countdown = section.querySelector('[data-lk-countdown]');
    let left = 10;
    const show = () => {
        if (!countdown) return;
        countdown.hidden = false;
        countdown.textContent = ` (${left} s)`;
    };
    const tick = () => {
        if (document.body.classList.contains('lk-tour-running')) {
            setTimeout(tick, 1000);
            return;
        }
        if (left <= 0) {
            location.href = section.dataset.lkReload;
            return;
        }
        show();
        left -= 1;
        setTimeout(tick, 1000);
    };
    tick();
})();
