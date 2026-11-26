"use strict";
// The flashed messages as toasts (partials/toasts.html, css/components/toasts.css):
// a close button on each, and the info / success ones go away by themselves when
// their timer bar ends (CSS animation, paused while the mouse is over them, and
// while the page is not on screen: a background tab).
// Doc: doc/ui/toasts.md
(() => {
    const close = (toast) => {
        if (toast.classList.contains('is-leaving')) return;
        toast.classList.add('is-leaving');
        const remove = () => {
            const stack = toast.parentElement;
            toast.remove();
            if (stack && !stack.children.length) stack.remove();
        };
        toast.addEventListener('animationend', remove, {once: true});
        // No animation (reduced motion): at once
        if (getComputedStyle(toast).animationName === 'none') remove();
    };
    // The timers run only while the page is really on screen: not while it waits in
    // a background tab, paused when another tab is shown
    const seen = () => {
        document.querySelector('.lk-toasts')?.classList.toggle('is-seen', document.visibilityState === 'visible');
    };
    const setup = () => {
        seen();
        document.addEventListener('visibilitychange', seen);
        document.querySelectorAll('.lk-toast').forEach(toast => {
            toast.querySelector('.lk-toast-close')?.addEventListener('click', () => close(toast));
            toast.querySelector('.lk-toast-timer')?.addEventListener('animationend', () => close(toast));
        });
    };
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', setup);
    } else {
        setup();
    }
})();
