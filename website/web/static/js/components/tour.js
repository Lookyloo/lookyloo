"use strict";
// Tutorial: a guided tour of the current page, for beginners.
// Each page lists its steps in its template (block tour of layouts/page.html,
// tour() of macros/tour.html: <script type="application/json" id="lk-tour">).
// The "Tutorial" menu of the site header starts the tour of the page, or the full
// tour of the site: every page of #lk-tour-full-pages, one after the other (the
// capture tree is not part of it). Steps whose element is missing or hidden are
// skipped. Doc: doc/ui/tour.md
(() => {
    // Full tour going on: {page: index in the list of pages} in sessionStorage
    const FULL_KEY = 'lk-tour-full';
    const session = {
        get: () => { try { return JSON.parse(sessionStorage.getItem(FULL_KEY)); } catch (e) { return null; } },
        set: (value) => { try { sessionStorage.setItem(FULL_KEY, JSON.stringify(value)); } catch (e) { /* not kept */ } },
        clear: () => { try { sessionStorage.removeItem(FULL_KEY); } catch (e) { /* nothing */ } },
    };
    // Pages of the full tour: the links of #lk-tour-full-pages (partials/header.html)
    function fullPages() {
        return [...document.querySelectorAll('#lk-tour-full-pages a')];
    }
    function goToFullPage(page) {
        const link = fullPages()[page];
        if (!link) {
            session.clear();   // past the last page: the end of the full tour
            return;
        }
        session.set({ page });
        link.click();
    }
    function startFull() {
        stop();
        goToFullPage(0);
    }
    // Stopped by the user (the Stop button): the full tour stops too
    function quit() { session.clear(); stop(); }

    let steps = [];
    let index = 0;
    let overlay = null;
    let spotlight = null;
    let card = null;

    function readSteps() {
        const data = document.getElementById('lk-tour');
        if (!data) return [];
        try { return JSON.parse(data.textContent) || []; } catch (e) { return []; }
    }

    function target(step) {
        if (!step.selector) return null;
        const element = document.querySelector(step.selector);
        if (!element) return null;
        // An entry of a menu opened by the step is hidden until the menu opens
        if (step.open) return document.querySelector(step.open) ? element : null;
        const box = element.getBoundingClientRect();
        if (!box.width && !box.height) return null;
        return element;
    }

    // Steps of this page that can be shown now (an element, or a general step without selector)
    function available() {
        return steps.filter(step => !step.selector || target(step));
    }

    // Menus (Bootstrap dropdowns) opened by the steps: open the one of the step, close the others
    let opened = null;
    function openMenu(selector) {
        if (opened && opened !== selector) {
            const previous = document.querySelector(opened);
            if (previous && window.bootstrap) bootstrap.Dropdown.getOrCreateInstance(previous).hide();
            opened = null;
        }
        // The header holding the menu (its own stacking context) goes above the veil
        document.querySelectorAll('.lk-tour-raised').forEach(element => element.classList.remove('lk-tour-raised'));
        if (selector) document.querySelector(selector)?.closest('.lk-header')?.classList.add('lk-tour-raised');
        if (!selector || !window.bootstrap) return;
        const toggle = document.querySelector(selector);
        if (!toggle) return;
        // After the click that triggered the step: Bootstrap closes menus on any click
        setTimeout(() => {
            bootstrap.Dropdown.getOrCreateInstance(toggle).show();
            requestAnimationFrame(place);
        }, 0);
        opened = selector;
    }

    function button(label, classes, action) {
        const element = document.createElement('button');
        element.type = 'button';
        element.className = classes;
        element.textContent = label;
        element.addEventListener('click', action);
        return element;
    }

    function build() {
        overlay = document.createElement('div');
        overlay.className = 'lk-tour-overlay';
        // A click outside the card does nothing: only the Stop button ends the tour
        spotlight = document.createElement('div');
        spotlight.className = 'lk-tour-spotlight';
        card = document.createElement('div');
        card.className = 'lk-tour-card';
        card.setAttribute('role', 'dialog');
        card.setAttribute('aria-modal', 'false');
        card.setAttribute('aria-labelledby', 'lk-tour-title');
        const progress = document.createElement('p');
        progress.className = 'lk-tour-progress';
        const title = document.createElement('h2');
        title.id = 'lk-tour-title';
        const text = document.createElement('p');
        text.className = 'lk-tour-text';
        const actions = document.createElement('div');
        actions.className = 'lk-tour-actions';
        const skip = button(session.get() ? 'Stop the full tour' : 'Stop the tour', 'btn btn-sm btn-link lk-tour-skip', quit);
        const previous = button('Previous', 'btn btn-sm btn-outline-secondary', () => go(index - 1));
        const next = button('Next', 'btn btn-sm btn-primary', () => go(index + 1));
        previous.dataset.role = 'previous';
        next.dataset.role = 'next';
        actions.append(skip, previous, next);
        card.append(progress, title, text, actions);
        document.body.append(overlay, spotlight, card);
        document.addEventListener('keydown', keys, true);
        window.addEventListener('resize', place);
        window.addEventListener('scroll', place, true);
    }

    function keys(event) {
        if (!card) return;
        // Esc does not stop it (only the Stop button); it is kept from the page
        if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); }
        else if (event.key === 'ArrowRight') { event.preventDefault(); go(index + 1); }
        else if (event.key === 'ArrowLeft') { event.preventDefault(); go(index - 1); }
    }

    function spot(box) {
        spotlight.hidden = false;
        spotlight.style.left = `${box.left - 6}px`;
        spotlight.style.top = `${box.top - 6}px`;
        spotlight.style.width = `${box.width + 12}px`;
        spotlight.style.height = `${box.height + 12}px`;
    }

    function place() {
        if (!card) return;
        const step = available()[index];
        const element = step && target(step);
        const margin = 12;
        // General step (no element): the whole page is veiled and blurred, the card centred
        overlay.classList.toggle('is-veiled', !element);
        if (!element) {
            spotlight.hidden = true;
            card.style.left = `${Math.max(16, (window.innerWidth - card.offsetWidth) / 2)}px`;
            card.style.top = `${Math.max(16, (window.innerHeight - card.offsetHeight) / 2)}px`;
            return;
        }
        const box = element.getBoundingClientRect();
        spot(box);
        // Entry of an opened menu: the card goes beside the menu, at the height of the entry
        const menu = step.open ? element.closest('.dropdown-menu') : null;
        if (menu) {
            const menu_box = menu.getBoundingClientRect();
            let left = menu_box.right + margin;
            if (left + card.offsetWidth > window.innerWidth - 16) left = menu_box.left - card.offsetWidth - margin;
            const top = Math.min(Math.max(16, box.top - 16), window.innerHeight - card.offsetHeight - 16);
            card.style.left = `${Math.max(16, left)}px`;
            card.style.top = `${top}px`;
            return;
        }
        // Below the element, else above, else on its side; always on screen
        let top = box.bottom + margin;
        if (top + card.offsetHeight > window.innerHeight - 16) top = box.top - card.offsetHeight - margin;
        if (top < 16) top = Math.min(window.innerHeight - card.offsetHeight - 16, Math.max(16, box.top));
        let left = box.left;
        if (box.bottom + margin + card.offsetHeight > window.innerHeight - 16 && box.top - card.offsetHeight - margin < 16) {
            left = box.right + margin;
            if (left + card.offsetWidth > window.innerWidth - 16) left = box.left - card.offsetWidth - margin;
        }
        left = Math.min(Math.max(16, left), window.innerWidth - card.offsetWidth - 16);
        card.style.left = `${left}px`;
        card.style.top = `${top}px`;
    }

    function go(to) {
        const list = available();
        const full = session.get();
        if (to >= list.length) {
            stop();
            if (full) goToFullPage(full.page + 1);
            return;
        }
        index = Math.max(0, to);
        const step = list[index];
        const pages = fullPages();
        card.querySelector('.lk-tour-progress').textContent = full
            ? `Full tour · page ${full.page + 1} / ${pages.length} · ${index + 1} / ${list.length}`
            : `Tutorial · ${index + 1} / ${list.length}`;
        card.querySelector('h2').textContent = step.title;
        card.querySelector('.lk-tour-text').textContent = step.text;
        card.querySelector('[data-role="previous"]').disabled = index === 0;
        const next_page = full && pages[full.page + 1];
        card.querySelector('[data-role="next"]').textContent = index < list.length - 1 ? 'Next'
            : next_page ? `Next page: ${next_page.textContent.trim()} →` : 'Finish';
        openMenu(step.open);
        const element = target(step);
        // Entry of an opened menu: the whole menu stays readable above the veil,
        // the entry gets its own outline (the spotlight goes under the menu)
        document.querySelectorAll('.lk-tour-target').forEach(node => node.classList.remove('lk-tour-target'));
        spotlight.classList.toggle('is-under', Boolean(step.open));
        if (step.open && element) element.classList.add('lk-tour-target');
        if (element && !step.open) element.scrollIntoView({ block: 'nearest', inline: 'nearest' });
        place();
        setTimeout(place, 320);   // after a smooth scroll / a menu opening
        card.querySelector('[data-role="next"]').focus({ preventScroll: true });
    }

    function start() {
        // The page can prepare itself (e.g. an example row on an empty list)
        document.dispatchEvent(new CustomEvent('lk-tour:before-start'));
        steps = readSteps();
        if (!available().length) return;
        stop();
        build();
        document.body.classList.add('lk-tour-running');
        go(0);
    }

    function stop() {
        const was_running = Boolean(card);
        openMenu(null);
        document.querySelectorAll('.lk-tour-target').forEach(node => node.classList.remove('lk-tour-target'));
        document.body.classList.remove('lk-tour-running');
        [overlay, spotlight, card].forEach(element => element?.remove());
        overlay = spotlight = card = null;
        document.removeEventListener('keydown', keys, true);
        window.removeEventListener('resize', place);
        window.removeEventListener('scroll', place, true);
        if (was_running) document.dispatchEvent(new CustomEvent('lk-tour:stop'));
    }

    // A tour starts by itself only during the full tour
    function autoStart() {
        const full = session.get();
        if (!full) return;
        // Left the full tour for another page (a link, the back button, an error page):
        // the full tour stops, the tour of this page does not start by itself
        const expected = fullPages()[full.page];
        if (!expected || expected.pathname !== location.pathname) {
            session.clear();
            return;
        }
        steps = readSteps();
        if (steps.length) setTimeout(start, 300);
        else goToFullPage(full.page + 1);   // a page without a tour: the next one
    }

    window.lkTour = { start, stop, startFull };

    document.addEventListener('DOMContentLoaded', () => {
        steps = readSteps();
        const start_button = document.getElementById('lk-tour-start');
        if (start_button) {
            start_button.disabled = !steps.length;
            start_button.addEventListener('click', () => setTimeout(start, 50));
        }
        // Every "full tour" button (Tutorial menu, home page of an empty instance)
        document.addEventListener('click', (event) => {
            if (event.target.closest('[data-lk-tour-full]')) setTimeout(startFull, 50);
        });
        setTimeout(autoStart, 300);
    });
})();
