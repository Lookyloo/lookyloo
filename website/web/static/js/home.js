"use strict";
// Home page (home/home.html): animated placeholder of the capture bar and
// logo whose first two eyes follow the mouse.

// Capture bar: example URLs "typed" in the placeholder, letter by letter.
// Only the placeholder changes (never the value); stops as soon as the field is
// focused or filled, and is disabled with prefers-reduced-motion.
document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('quick-capture-url');
    if (!input || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        return;
    }
    const examples = [
        'https://suspicious-link.example/login',
        'https://bit.ly/3xAmpl3',
        'http://paypal-account-verify.example.net/',
        'https://your-bank.example.com/secure/update',
        'https://www.circl.lu',
    ];
    const original = input.placeholder;
    let stopped = false;
    let timer = null;
    const stop = () => {
        stopped = true;
        clearTimeout(timer);
        input.placeholder = original;
    };
    input.addEventListener('focus', stop, { once: true });
    input.addEventListener('input', stop, { once: true });

    let example = 0;
    let length = 0;
    let deleting = false;
    const step = () => {
        if (stopped) {
            return;
        }
        const text = examples[example];
        length += deleting ? -1 : 1;
        input.placeholder = text.slice(0, length) + (deleting ? '' : '▍');
        let delay = deleting ? 25 : 55 + Math.random() * 60;
        if (!deleting && length === text.length) {
            deleting = true;
            delay = 1800;            // pause on the full URL
        } else if (deleting && length === 0) {
            deleting = false;
            example = (example + 1) % examples.length;
            delay = 400;
        }
        timer = setTimeout(step, delay);
    };
    timer = setTimeout(step, 800);
});

// Home logo: the pupils of the first two "o" follow the mouse. They start at the
// position drawn in the logo and move inside their ring (max ~11px of the 706px
// logo). Static with prefers-reduced-motion. Positions: data-* in home/home.html.
document.addEventListener('DOMContentLoaded', () => {
    const logo = document.querySelector('[data-lk-eyes]');
    if (!logo) {
        return;
    }
    const width = parseFloat(logo.dataset.width);
    const height = parseFloat(logo.dataset.height);
    const maxOffset = 11;
    const pupils = [...logo.querySelectorAll('.lk-logo-pupil')].map(el => ({
        el,
        ringX: parseFloat(el.dataset.ringX), ringY: parseFloat(el.dataset.ringY),
        restX: parseFloat(el.dataset.x), restY: parseFloat(el.dataset.y),
    }));
    const place = (pupil, x, y) => {
        pupil.el.style.left = `${(x / width) * 100}%`;
        pupil.el.style.top = `${(y / height) * 100}%`;
    };
    const rest = () => pupils.forEach(p => place(p, p.restX, p.restY));
    rest();
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        return;
    }
    let frame = null;
    let mouse = null;
    const update = () => {
        frame = null;
        const rect = logo.getBoundingClientRect();
        const scale = rect.width / width;
        pupils.forEach(p => {
            // Ring centre on screen -> direction of the mouse
            const dx = mouse.x - (rect.left + p.ringX * scale);
            const dy = mouse.y - (rect.top + p.ringY * scale);
            const distance = Math.hypot(dx, dy);
            const reach = Math.min(maxOffset, distance / scale / 12);
            const angle = Math.atan2(dy, dx);
            place(p, p.ringX + Math.cos(angle) * reach, p.ringY + Math.sin(angle) * reach);
        });
    };
    document.addEventListener('pointermove', event => {
        mouse = {x: event.clientX, y: event.clientY};
        if (!frame) {
            frame = requestAnimationFrame(update);
        }
    }, { passive: true });
    document.documentElement.addEventListener('pointerleave', rest);
});
