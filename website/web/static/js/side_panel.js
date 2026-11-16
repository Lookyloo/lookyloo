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
// unique. One width for the whole panel (drag the left edge), remembered. A tab can be detached in its own window; closing that window closes
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
    // One width for the whole panel, whatever the tab (switching tabs never moves it)
    const WIDTH_KEY = 'lk-side-panel-width';
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
    let panel_width = (() => {
        const saved = parseInt(storage.get(WIDTH_KEY), 10);
        return clampWidth(Number.isFinite(saved) ? saved : Math.round(window.innerWidth * 0.4));
    })();

    // The page knows the room the panel takes (js/tree.js centres in what is left,
    // css/tree.css moves the tree controls and the legend)
    const applyWidth = () => {
        const docked = tabs.filter(tab => !tab.win);
        const width = current && !current.win ? panel_width : 0;
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
        // (the opener can be inside a vitrine component: its shadow host is in the panel)
        const in_panel = opener && (opener.getRootNode().host || opener).closest?.('.lk-side-panel-content');
        const value = in_panel
            ? opener.textContent.replace(/[\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '').replace(/\s*\n\s*/g, '').replace(/\s+/g, ' ').trim() : '';
        if (value && value.length < 80) {
            title = `${title}: ${value}`;
        }
        return title;
    };

    // ---- Content ----

    // The eyes of the logo (macros/loader.html, template in tree/side_panel.html)
    const loader_template = document.getElementById('lk-side-panel-loader');
    const loading = () => {
        const wrap = document.createElement('div');
        wrap.className = 'lk-side-panel-loading';
        if (loader_template) {
            wrap.appendChild(loader_template.content.cloneNode(true));
        } else {
            wrap.textContent = 'Loading…';
        }
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
        // Vitrine components of the Capture panels (js/capture_panels.js)
        if (typeof setupCapturePanels === 'function') setupCapturePanels(body);
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
                if (swallow_tab_click) return;   // the end of a drag
                if (tab.win && !tab.win.closed) {
                    tab.win.focus();
                } else {
                    activate(tab);
                }
            });
            button.addEventListener('auxclick', (event) => {
                if (event.button === 1) closeTab(tab);   // middle click, like a browser
            });
            // Reorder: drag a tab before / after another (pointer events), or Shift + ← / →
            button.addEventListener('pointerdown', (event) => startTabDrag(event, tab, button));
            button.addEventListener('keydown', (event) => {
                if (!event.shiftKey || !['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
                event.preventDefault();
                const index = tabs.indexOf(tab);
                const other = tabs[index + (event.key === 'ArrowLeft' ? -1 : 1)];
                if (other) {
                    moveTab(tab, other, event.key === 'ArrowRight');
                    tabs_bar.querySelector('[aria-selected="true"]')?.focus();
                }
            });
            return button;
        }));
        tabs_bar.querySelector('[aria-selected="true"]')?.scrollIntoView({block: 'nearest', inline: 'nearest'});
        saveState();
    };

    // Drag a tab along the bar: a line shows where it goes, dropped on release.
    // A press without movement stays a click (shows the tab).
    let tab_drag = null;
    let swallow_tab_click = false;
    function startTabDrag(event, tab, button) {
        if (event.button !== 0 || event.target.closest('.lk-side-tab-close')) return;
        tab_drag = {tab, button, x: event.clientX, moving: false, target: null, after: false};
        const clear = () => tabs_bar.querySelectorAll('.lk-side-tab').forEach(t => t.classList.remove('drop-before', 'drop-after'));
        const move = (e) => {
            if (!tab_drag) return;
            if (!tab_drag.moving) {
                if (Math.abs(e.clientX - tab_drag.x) < 5) return;
                tab_drag.moving = true;
                button.classList.add('is-dragged');
            }
            e.preventDefault();
            clear();
            // The tab under the pointer (along the bar only)
            const others = [...tabs_bar.querySelectorAll('.lk-side-tab')];
            const over = others.find(t => {
                const box = t.getBoundingClientRect();
                return e.clientX >= box.left && e.clientX <= box.right;
            }) || (e.clientX < others[0].getBoundingClientRect().left ? others[0] : others[others.length - 1]);
            const index = others.indexOf(over);
            if (over === button || index === -1) {
                tab_drag.target = null;
                return;
            }
            const box = over.getBoundingClientRect();
            tab_drag.target = tabs[index];
            tab_drag.after = e.clientX > box.left + box.width / 2;
            over.classList.add(tab_drag.after ? 'drop-after' : 'drop-before');
        };
        const up = () => {
            window.removeEventListener('pointermove', move);
            window.removeEventListener('pointerup', up);
            window.removeEventListener('blur', up);
            const drag = tab_drag;
            tab_drag = null;
            clear();
            button.classList.remove('is-dragged');
            if (drag?.moving) {
                swallow_tab_click = true;
                setTimeout(() => { swallow_tab_click = false; }, 0);
                if (drag.target) moveTab(drag.tab, drag.target, drag.after);
            }
        };
        window.addEventListener('pointermove', move);
        window.addEventListener('pointerup', up);
        window.addEventListener('blur', up);
    }

    // Move a tab before or after another one (the order is kept in the URL too)
    function moveTab(tab, target, after) {
        const from = tabs.indexOf(tab);
        if (from === -1 || tab === target) return;
        tabs.splice(from, 1);
        const to = tabs.indexOf(target) + (after ? 1 : 0);
        tabs.splice(to, 0, tab);
        renderTabs();
    }

    // ---- The open tabs in the URL (#panels=...): a reload opens them again ----
    // [kind (modal id) | 'node', remote URL | hostnode uuid | null, title], and the
    // index of the current tab. Detached tabs are not kept.
    const saveState = () => {
        if (restoring) return;
        const docked = tabs.filter(tab => !tab.win);
        const state = {
            t: docked.map(tab => tab.page ? ['node', tab.node, tab.title] : [tab.kind, tab.url, tab.title]),
            a: Math.max(0, docked.indexOf(current)),
        };
        const hash = docked.length ? `#panels=${encodeURIComponent(JSON.stringify(state))}` : '';
        history.replaceState(history.state, '', `${location.pathname}${location.search}${hash}`);
    };

    // The hash comes from a link anyone can write: only the panels of this page
    // and the read-only detail pages are opened again (some GET routes of
    // Lookyloo change things: remove, rebuild...)
    const DETAIL_PATHS = ['/urls/', '/hostnames/', '/ips/', '/favicon_details/', '/capture_hash_details/',
                          '/body_hashes/', '/identifier_details/', '/cloudflare_ns/'];
    const allowedRemote = (url) => {
        if (typeof url !== 'string') return false;
        let parsed;
        try {
            parsed = new URL(url, location.origin);
        } catch (e) {
            return false;
        }
        if (parsed.origin !== location.origin) return false;
        if ([...document.querySelectorAll('[data-remote]')].some(el => el.dataset.remote === url)) return true;
        return DETAIL_PATHS.some(prefix => parsed.pathname.startsWith(prefix));
    };
    const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

    let restoring = false;
    function restore() {
        const match = location.hash.match(/^#panels=(.+)$/);
        if (!match) return;
        let state;
        try {
            state = JSON.parse(decodeURIComponent(match[1]));
        } catch (e) {
            return;
        }
        if (!state || !Array.isArray(state.t)) return;
        restoring = true;
        try {
            state.t.slice(0, 20).forEach(entry => {
                if (!Array.isArray(entry)) return;
                const [kind, value, title] = entry;
                const label = typeof title === 'string' ? title.slice(0, 200) : 'Panel';
                if (kind === 'node') {
                    if (typeof value === 'string' && UUID.test(value)) {
                        openPage(`/tree/${treeUUID}/host/${value}${location.search}`, label, 'hostnode', value);
                    }
                    return;
                }
                const modal = typeof kind === 'string' && /^[A-Za-z][\w-]*$/.test(kind) && document.getElementById(kind);
                if (!modal || !modal.classList.contains('modal') || KEPT_AS_MODALS.has(kind)) return;
                if (value === null) {
                    openModal(modal, null, label, {focus: false});
                } else if (allowedRemote(value)) {
                    openModal(modal, value, label, {focus: false});
                }
            });
        } finally {
            restoring = false;
        }
        const docked = tabs.filter(tab => !tab.win);
        const active = docked[Number.isInteger(state.a) ? state.a : 0];
        if (active) activate(active);
        saveState();
    }

    function activate(tab) {
        if (current && current !== tab && !current.win) {
            if (current.page) {
                current.content.hidden = true;   // a frame removed from the page would reload
            } else {
                current.content.remove();   // kept aside, with its state
            }
        }
        current = tab;
        if (!tab.win) {
            // Other contents out (frames only hidden), this one in
            body.querySelectorAll(':scope > .lk-side-panel-content:not(.is-page)').forEach(el => {
                if (el !== tab.content) el.remove();
            });
            if (tab.content.parentElement !== body) body.appendChild(tab.content);
            tab.content.hidden = false;
            if (tab.pending_setup) {
                tab.pending_setup = false;
                setupContent();
            }
        }
        renderTabs();
        applyWidth();
        syncNode();
    }

    // The node of the current tab (details of a node) is selected in the tree
    const syncNode = () => {
        if (!window.lkTree) return;
        if (current && current.node && !current.win) {
            window.lkTree.selectNode(current.node);
        } else {
            window.lkTree.clearNodeSelection();
        }
    };

    // A whole page in a tab (the details of a node: tree/hostname_popup.html), in a
    // frame. It talks to the capture page with window.parent (js/generic.js).
    function openPage(url, title, kind, node=null) {
        closeDropdowns();
        const existing = tabs.find(tab => tab.page && tab.url === url);
        if (existing) {
            if (existing.win && !existing.win.closed) {
                existing.win.focus();
            } else {
                activate(existing);
            }
            return;
        }
        const tab = {
            id: next_id++, kind, url, page: true, modal: null, win: null, title, node,
            content: document.createElement('div'),
        };
        tab.content.className = 'lk-side-panel-content is-page';
        const frame = document.createElement('iframe');
        frame.src = url;
        frame.title = title;
        tab.content.appendChild(frame);
        tabs.push(tab);
        activate(tab);
    }
    window.lkSidePanel = { openPage, restore };

    function open(modal, opener) {
        openModal(modal, opener?.dataset.remote || null, titleOf(modal, opener));
    }

    function openModal(modal, url, title, {focus = true} = {}) {
        closeDropdowns();
        const kind = modal.id;
        // Already open: back to it (a remote one is loaded again, a fresh view)
        const existing = tabs.find(tab => !tab.page && tab.kind === kind && tab.url === url);
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
            id: next_id++, kind, url, modal, win: null, title,
            content: document.createElement('div'),
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
        if (focus) panel.focus({preventScroll: true});
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
        if (!tab.url && !tab.page) {
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
        syncNode();
    }

    function closeAll() {
        [...tabs].forEach(closeTab);
    }

    // ---- Detach: the tab in its own window ----

    const detach = (tab) => {
        if (!tab || tab.win) {
            return;
        }
        if (tab.page) {
            // The page itself in a window, like the former pop-up (window.opener works)
            const popup = window.open(tab.url, '_blank', `width=${Math.max(1024, Math.round(panel_width))},height=768`);
            if (popup) {
                popup.focus();
                closeTab(tab);
            }
            return;
        }
        const win = window.open('', `lk-panel-${treeUUID}-${tab.id}`,
                                `width=${Math.round(panel_width)},height=${Math.round(window.innerHeight * 0.8)}`);
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
        syncNode();
    };

    // ---- Openers ----

    // On window, capture phase: runs before Bootstrap's own listener
    function onOpenerClick(event) {
        // composedPath: also the links drawn inside a vitrine component (shadow DOM:
        // event.target is the component itself), like the cookie names of the storage state
        const opener = event.composedPath().find(node => node instanceof Element && node.matches('[data-bs-toggle="modal"]'))
            || event.target.closest?.('[data-bs-toggle="modal"]');
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

    // ---- Width of the panel: drag the left edge (or arrows on the handle) ----

    const setCurrentWidth = (width) => {
        if (!current) {
            return;
        }
        panel_width = clampWidth(width);
        applyWidth();
    };
    const saveCurrentWidth = () => {
        storage.set(WIDTH_KEY, String(Math.round(panel_width)));
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
        setCurrentWidth(panel_width + (event.key === 'ArrowLeft' ? 40 : -40));
        saveCurrentWidth();
    });
    window.addEventListener('resize', () => {
        panel_width = clampWidth(panel_width);
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
