"use strict";
// Side panel of the capture page (tree/side_panel.html), at the right of the tree.
// Doc: doc/ui/side-panel.md
//
// The panels of the menus are still Bootstrap modals in tree/tree.html (IDs,
// data-remote unchanged). A click on anything that would open one of them
// (data-bs-toggle="modal") is taken over here and opens a tab instead:
// - remote panels (the opener has data-remote): the tab loads its own copy of
//   the content, like js/tree_modals.js does for the modal, so two hostnames
//   (or two favicons...) can be open side by side;
// - panels written in the page (details, screenshot, forms): their body is
//   moved into the tab, and back into the modal when the tab is closed.
// Only the content of the current tab is in the page: the others are kept
// aside (state kept), so the IDs the tables rely on (js/render_tables.js) stay
// unique. Each tab has its own width (drag the left edge), remembered per kind
// of panel. A tab can be detached in its own window; closing that window closes
// the tab.
(() => {
    const panel = document.getElementById('lk-side-panel');
    if (!panel) {
        return;
    }
    const tabs_bar = document.getElementById('lk-side-panel-tabs');
    const body = document.getElementById('lk-side-panel-body');
    const handle = document.getElementById('lk-side-panel-resize');
    const root = document.documentElement;
    // Real dialogs, kept as Bootstrap modals
    const KEPT_AS_MODALS = new Set([]);
    const MIN_WIDTH = 320;
    const WIDTH_KEY = (kind) => `lk-side-panel-width|${kind}`;
    const storage = {
        get: (key) => { try { return localStorage.getItem(key); } catch (e) { return null; } },
        set: (key, value) => { try { localStorage.setItem(key, value); } catch (e) { /* not kept */ } },
    };

    // {id, kind (modal id), title, url (remote) | null, content (element), modal, width, win}
    const tabs = [];
    let current = null;
    let next_id = 1;

    const maxWidth = () => Math.max(MIN_WIDTH, window.innerWidth - 240);
    const clampWidth = (width) => Math.min(Math.max(width, MIN_WIDTH), maxWidth());
    const defaultWidth = (kind) => {
        const saved = parseInt(storage.get(WIDTH_KEY(kind)), 10);
        return clampWidth(Number.isFinite(saved) ? saved : Math.round(window.innerWidth * 0.4));
    };

    // The page knows the room the panel takes (js/tree.js centres in what is left,
    // css/tree.css moves the tree controls and the legend)
    const applyWidth = () => {
        const docked = tabs.filter(tab => !tab.win);
        const width = current && !current.win ? current.width : 0;
        panel.style.width = `${width}px`;
        root.style.setProperty('--lk-side-panel-space', docked.length ? `${width}px` : '0px');
        panel.hidden = docked.length === 0;
        document.body.classList.toggle('has-side-panel', docked.length > 0);
    };

    const closeDropdowns = () => {
        document.querySelectorAll('[data-bs-toggle="dropdown"].show').forEach(toggle => {
            bootstrap.Dropdown.getOrCreateInstance(toggle).hide();
        });
    };

    const titleOf = (modal, opener) => {
        let title = modal.querySelector('.modal-title')?.textContent.trim() || 'Panel';
        // From inside a panel (a hostname, a favicon...): the value clicked, to tell the tabs apart
        // Spaces collapsed, invisible direction marks of the shortened values removed
        const value = opener?.closest('.lk-side-panel-content')
            ? opener.textContent.replace(/[\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '').replace(/\s*\n\s*/g, '').replace(/\s+/g, ' ').trim() : '';
        if (value && value.length < 80) {
            title = `${title}: ${value}`;
        }
        return title;
    };

    // ---- Content ----

    const loading = () => {
        const wrap = document.createElement('div');
        wrap.className = 'lk-side-panel-loading';
        const spinner = document.createElement('div');
        spinner.className = 'spinner-border spinner-border-sm';
        spinner.setAttribute('role', 'status');
        const label = document.createElement('span');
        label.textContent = 'Loading…';
        wrap.append(spinner, label);
        return wrap;
    };

    // Same as the loader of the modals (js/tree_modals.js): HTML rendered (and
    // escaped) by Flask, then the tables and listeners of the fragments
    const loadRemote = (tab) => {
        tab.content.replaceChildren(loading());
        fetch(tab.url)
            .then(response => {
                if (!response.ok) {
                    throw new Error(response.statusText);
                }
                return response.text();
            })
            .then(html => {
                tab.content.innerHTML = html;
                if (tab !== current || tab.win) {
                    // Not shown: the tables are set up when it is
                    tab.pending_setup = true;
                    return;
                }
                setupContent();
            })
            .catch(() => {
                const message = document.createElement('p');
                message.className = 'text-danger p-3';
                message.textContent = 'This panel could not be loaded.';
                tab.content.replaceChildren(message);
            });
    };

    const setupContent = () => {
        if (typeof renderTables === 'function') renderTables();
        if (typeof submitPandoraListener === 'function') submitPandoraListener();
        if (typeof mispSelector === 'function') mispSelector();
        if (typeof downloadSvg === 'function') {
            document.getElementById('dlTreeAsSVG')?.addEventListener('click', downloadSvg);
        }
    };

    // Panel written in the page: its body (and footer) go into the tab
    const borrowStatic = (tab) => {
        const parts = tab.modal.querySelectorAll(':scope .modal-body, :scope .modal-footer');
        tab.borrowed = [...parts].map(part => ({part, parent: part.parentElement, next: part.nextSibling}));
        tab.borrowed.forEach(({part}) => tab.content.appendChild(part));
        // What Bootstrap would send, for the listeners of these panels
        tab.modal.dispatchEvent(new Event('show.bs.modal'));
        tab.modal.dispatchEvent(new Event('shown.bs.modal'));
    };
    const giveBackStatic = (tab) => {
        (tab.borrowed || []).forEach(({part, parent, next}) => parent.insertBefore(part, next));
        tab.modal.dispatchEvent(new Event('hidden.bs.modal'));
    };

    // ---- Tabs ----

    const renderTabs = () => {
        tabs_bar.replaceChildren(...tabs.map(tab => {
            const button = document.createElement('div');
            button.className = 'lk-side-tab';
            button.setAttribute('role', 'tab');
            button.setAttribute('aria-selected', tab === current ? 'true' : 'false');
            button.tabIndex = tab === current ? 0 : -1;
            button.title = tab.win ? `${tab.title} (in its own window)` : tab.title;
            button.classList.toggle('is-detached', Boolean(tab.win));
            const label = document.createElement('span');
            label.className = 'lk-side-tab-label';
            label.textContent = tab.title;
            const close = document.createElement('button');
            close.type = 'button';
            close.className = 'lk-side-tab-close';
            close.setAttribute('aria-label', `Close ${tab.title}`);
            close.textContent = '×';
            close.addEventListener('click', (event) => {
                event.stopPropagation();
                closeTab(tab);
            });
            button.append(label, close);
            button.addEventListener('click', () => {
                if (tab.win && !tab.win.closed) {
                    tab.win.focus();
                } else {
                    activate(tab);
                }
            });
            button.addEventListener('auxclick', (event) => {
                if (event.button === 1) closeTab(tab);   // middle click, like a browser
            });
            return button;
        }));
        tabs_bar.querySelector('[aria-selected="true"]')?.scrollIntoView({block: 'nearest', inline: 'nearest'});
    };

    function activate(tab) {
        if (current && current !== tab && !current.win) {
            current.content.remove();   // kept aside, with its state
        }
        current = tab;
        if (!tab.win) {
            body.replaceChildren(tab.content);
            if (tab.pending_setup) {
                tab.pending_setup = false;
                setupContent();
            }
        }
        renderTabs();
        applyWidth();
    }

    function open(modal, opener) {
        closeDropdowns();
        const kind = modal.id;
        const url = opener?.dataset.remote || null;
        // Already open: back to it (a remote one is loaded again, a fresh view)
        const existing = tabs.find(tab => tab.kind === kind && tab.url === url);
        if (existing) {
            if (existing.win && !existing.win.closed) {
                existing.win.focus();
                return;
            }
            activate(existing);
            if (existing.url) loadRemote(existing);
            return;
        }
        const tab = {
            id: next_id++, kind, url, modal, win: null,
            title: titleOf(modal, opener),
            content: document.createElement('div'),
            width: defaultWidth(kind),
        };
        tab.content.className = 'lk-side-panel-content';
        tabs.push(tab);
        if (url) {
            activate(tab);
            loadRemote(tab);
        } else {
            borrowStatic(tab);
            activate(tab);
        }
        panel.focus({preventScroll: true});
    }

    function closeTab(tab) {
        const index = tabs.indexOf(tab);
        if (index === -1) {
            return;
        }
        tabs.splice(index, 1);
        if (tab.win && !tab.win.closed) {
            tab.closing = true;
            tab.win.close();
        }
        if (!tab.url) {
            giveBackStatic(tab);
        }
        tab.content.remove();
        if (tab === current) {
            current = null;
            const docked = tabs.filter(t => !t.win);
            const next = docked[Math.min(index, docked.length - 1)] || null;
            if (next) {
                activate(next);
                return;
            }
            body.replaceChildren();
        }
        renderTabs();
        applyWidth();
    }

    function closeAll() {
        [...tabs].forEach(closeTab);
    }

    // ---- Detach: the tab in its own window ----

    const detach = (tab) => {
        if (!tab || tab.win) {
            return;
        }
        const win = window.open('', `lk-panel-${treeUUID}-${tab.id}`,
                                `width=${Math.round(tab.width)},height=${Math.round(window.innerHeight * 0.8)}`);
        if (!win) {
            return;   // pop-up blocked
        }
        const doc = win.document;
        doc.documentElement.setAttribute('data-bs-theme', root.getAttribute('data-bs-theme') || 'light');
        doc.title = tab.title;
        // Same stylesheets as the capture page (same origin, same integrity)
        document.querySelectorAll('link[rel="stylesheet"]').forEach(link => {
            const copy = doc.createElement('link');
            copy.rel = 'stylesheet';
            copy.href = link.href;
            if (link.integrity) copy.integrity = link.integrity;
            if (link.crossOrigin) copy.crossOrigin = link.crossOrigin;
            doc.head.appendChild(copy);
        });
        doc.body.className = 'lk-detached-panel';
        const heading = doc.createElement('h1');
        heading.className = 'lk-detached-title';
        heading.textContent = tab.title;
        doc.body.appendChild(heading);
        doc.body.appendChild(doc.adoptNode(tab.content));
        tab.win = win;
        // Links that open a panel, inside the window: a tab of the capture page
        doc.addEventListener('click', onOpenerClick, true);
        // Its "Close" buttons close the window (and the tab)
        doc.addEventListener('click', (event) => {
            if (event.target.closest('[data-bs-dismiss="modal"]')) {
                event.preventDefault();
                closeTab(tab);
            }
        }, true);
        win.addEventListener('pagehide', () => {
            if (!tab.closing) closeTab(tab);
        });
        // The next docked tab is shown in the panel
        if (current === tab) {
            current = null;
            const docked = tabs.filter(t => !t.win);
            if (docked.length) {
                activate(docked[docked.length - 1]);
            } else {
                body.replaceChildren();
            }
        }
        renderTabs();
        applyWidth();
    };

    // ---- Openers ----

    // On window, capture phase: runs before Bootstrap's own listener
    function onOpenerClick(event) {
        const opener = event.target.closest('[data-bs-toggle="modal"]');
        if (!opener) {
            return;
        }
        const target = (opener.dataset.bsTarget || opener.getAttribute('href') || '').replace(/^#/, '');
        const modal = target && document.getElementById(target);
        if (!modal || !modal.classList.contains('modal') || KEPT_AS_MODALS.has(target)) {
            return;
        }
        event.preventDefault();
        event.stopPropagation();
        open(modal, opener);
    }
    window.addEventListener('click', onOpenerClick, true);

    // The close buttons of the borrowed panels (data-bs-dismiss="modal")
    body.addEventListener('click', (event) => {
        if (event.target.closest('[data-bs-dismiss="modal"]') && current) {
            event.preventDefault();
            event.stopPropagation();
            closeTab(current);
        }
    }, true);

    document.getElementById('lk-side-panel-close-all').addEventListener('click', closeAll);
    document.getElementById('lk-side-panel-detach').addEventListener('click', () => detach(current));

    // Esc closes the current tab (not while typing, not over a real modal)
    window.addEventListener('keydown', (event) => {
        if (event.key !== 'Escape' || panel.hidden || !current || document.querySelector('.modal.show')) {
            return;
        }
        if (event.target.closest('input, textarea, select')) {
            return;
        }
        event.stopImmediatePropagation();
        closeTab(current);
    }, true);

    // ---- Width of the current tab: drag the left edge (or arrows on the handle) ----

    const setCurrentWidth = (width) => {
        if (!current) {
            return;
        }
        current.width = clampWidth(width);
        applyWidth();
    };
    const saveCurrentWidth = () => {
        if (current) storage.set(WIDTH_KEY(current.kind), String(Math.round(current.width)));
    };
    // Followed on the whole window (the handle moves with the width, and its
    // pointer capture was dropped after the first move)
    handle.addEventListener('pointerdown', (event) => {
        if (event.button !== 0) {
            return;
        }
        event.preventDefault();
        panel.classList.add('is-resizing');
        const move = (e) => setCurrentWidth(window.innerWidth - e.clientX);
        const up = () => {
            window.removeEventListener('pointermove', move);
            window.removeEventListener('pointerup', up);
            window.removeEventListener('blur', up);
            panel.classList.remove('is-resizing');
            saveCurrentWidth();
        };
        window.addEventListener('pointermove', move);
        window.addEventListener('pointerup', up);
        window.addEventListener('blur', up);
    });
    handle.addEventListener('keydown', (event) => {
        if (!current || !['ArrowLeft', 'ArrowRight'].includes(event.key)) {
            return;
        }
        event.preventDefault();
        setCurrentWidth(current.width + (event.key === 'ArrowLeft' ? 40 : -40));
        saveCurrentWidth();
    });
    window.addEventListener('resize', () => {
        tabs.forEach(tab => { tab.width = clampWidth(tab.width); });
        applyWidth();
    });

    // Closing the capture page closes the detached windows
    window.addEventListener('pagehide', () => {
        tabs.forEach(tab => {
            if (tab.win && !tab.win.closed) {
                tab.closing = true;
                tab.win.close();
            }
        });
    });
})();
