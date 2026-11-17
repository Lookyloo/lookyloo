// Panels of the Capture menu (tree/tree.html, tree/modals/*), restyled with the
// vitrine web components (vendor/vitrine/, tools/3rdparty.py):
// <vt-json> (MISP export, IndexedDB), <vt-table> (cookies, local storage, OPFS,
// WebAuthn credentials), <vt-stats> (statistics), <vt-log> (console messages).
// Loaded as a module by the capture page and by the "Open as a page" versions of
// the panels. The content of a panel is set up by setupCapturePanels(root), called
// when it is shown (js/side_panel.js) or when the page loads. Doc: doc/ui/capture-panels.md
import { configure } from '../vendor/vitrine/esm/api.js';
import '../vendor/vitrine/esm/vt-json.js';
import '../vendor/vitrine/esm/vt-table.js';
import '../vendor/vitrine/esm/vt-stats.js';
import '../vendor/vitrine/esm/vt-log.js';

const base = new URL('../vendor/vitrine/', import.meta.url).href;
// Light / dark like the rest of Lookyloo (data-bs-theme on <html>, js/theme_toggle.js)
const lookylooTheme = () => (document.documentElement.getAttribute('data-bs-theme') === 'dark' ? 'dark' : 'light');
// MISP exports embed the resources of the capture: vitrine's maximum (50 MiB)
const MAX_JSON = 52428800;
configure({
    languagesUrl: `${base}languages/`,
    syntaxThemesUrl: `${base}syntax-themes/`,
    vendorUrl: `${base}vendor/`,
    theme: lookylooTheme(),
    maxSize: MAX_JSON,
});
new MutationObserver(() => configure({ theme: lookylooTheme() }))
    .observe(document.documentElement, { attributes: true, attributeFilter: ['data-bs-theme'] });

// ---- Helpers ----

const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
};

// Same date as the tables of the site (render_datetime_with_tz, js/generic.js)
const datetime = (value) => (typeof render_datetime_with_tz === 'function' ? render_datetime_with_tz(value) : new Date(value).toString());

// Copy to the clipboard, and say it on the button for 2 seconds
function copyWithFeedback(button, text) {
    const label = button.querySelector('span') || button;
    const before = label.textContent;
    const show = (message, ok) => {
        label.textContent = message;
        button.classList.toggle('is-copied', ok);
        button.classList.toggle('is-copy-failed', !ok);
        clearTimeout(button.lkCopyTimer);
        button.lkCopyTimer = setTimeout(() => {
            label.textContent = before;
            button.classList.remove('is-copied', 'is-copy-failed');
        }, 2000);
    };
    if (!navigator.clipboard) {
        show('Copy failed', false);
        return;
    }
    navigator.clipboard.writeText(text).then(() => show('Copied', true), () => show('Copy failed', false));
}

const downloadText = (text, filename, type = 'application/json') => {
    const link = document.createElement('a');
    link.href = URL.createObjectURL(new Blob([text], { type }));
    link.download = filename;
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
};

// ---- Tables (<vt-table data-lk-table="kind">, rows in the next <script type="application/json">) ----

// true / false / null / None (a boolean, or a text that says it): styled like in
// the JSON viewer (vitrine's keyword colour, monospace), in every table
const LITERAL = /^(true|false|null|none|undefined)$/i;
const literal = (value) => {
    const text = typeof value === 'boolean' ? String(value)
        : (value === null ? 'null' : (typeof value === 'string' && LITERAL.test(value.trim()) ? value.trim() : null));
    if (text === null) return null;
    const span = document.createElement('span');
    span.className = 'lk-literal';
    span.textContent = text;
    // Inside the shadow DOM of the table: CSSOM, with vitrine's own variable
    span.style.color = 'var(--_syntax-keyword, var(--vt-syntax-keyword, #7a3ec8))';
    span.style.fontFamily = 'var(--vt-font-mono, ui-monospace, monospace)';
    return span;
};
const literalOr = (value) => literal(value) ?? value;

// A text with "key: True" pairs (the details of a partitioned cookie): the values styled
const literalsInText = (value) => {
    if (typeof value !== 'string' || !/:\s*(true|false|none|null)\b/i.test(value)) return value || '—';
    const wrap = document.createElement('span');
    let last = 0;
    for (const match of value.matchAll(/(:\s*)(true|false|none|null)\b/gi)) {
        const start = match.index + match[1].length;
        wrap.append(value.slice(last, start), literal(match[2]));
        last = start + match[2].length;
    }
    wrap.append(value.slice(last));
    return wrap;
};

// Booleans: filtered with Yes / No, shown as true / false
const yesNo = { type: 'boolean', align: 'center', width: 100, render: (value) => literalOr(Boolean(value)) };

// A value that is JSON (an object or an array, often in the storage): pretty, in a
// small <vt-json>; any other value as text
const jsonOrText = (value) => {
    const word = literal(value);
    if (word) return word;
    if (typeof value !== 'string') return value;
    const text = value.trim();
    if (!(text.startsWith('{') && text.endsWith('}')) && !(text.startsWith('[') && text.endsWith(']'))) return value;
    try {
        JSON.parse(text);
    } catch (e) {
        return value;
    }
    const viewer = document.createElement('vt-json');
    viewer.className = 'lk-vitrine';
    viewer.setAttribute('view', 'raw');
    viewer.setAttribute('max-height', '320px');
    viewer.content = text;
    return viewer;
};

// A link that opens a panel (js/side_panel.js reads the click through the shadow DOM)
const panelLink = (text, target, remote) => {
    const link = el('a', 'lk-table-link', text);
    link.href = `#${target}`;
    link.setAttribute('role', 'button');
    link.dataset.bsToggle = 'modal';
    link.dataset.bsTarget = `#${target}`;
    link.dataset.remote = remote;
    return link;
};

const TABLES = {
    cookies: [
        { key: 'frequency', label: 'Captures', type: 'number', width: 150 },
        { key: 'name', label: 'Name', width: 180,
          render: (value, row) => (row.detail ? panelLink(value, 'cookieNameModal', row.detail) : value) },
        { key: 'value', label: 'Value', width: 280, render: jsonOrText },
        { key: 'domain', label: 'Domain', width: 160 },
        { key: 'partition', label: 'CHIPS', width: 160, render: literalsInText },
        { key: 'expires', label: 'Expires', type: 'date', width: 200,
          format: (value) => (value > 0 ? datetime(value) : 'Session') },
        { key: 'path', label: 'Path', width: 90 },
        { key: 'httpOnly', label: 'HTTP only', ...yesNo },
        { key: 'secure', label: 'Secure', ...yesNo },
        { key: 'sameSite', label: 'Same site', width: 100 },
    ],
    local_storage: [
        { key: 'name', label: 'Name', width: 220 },
        { key: 'value', label: 'Value', render: jsonOrText },
    ],
    opfs: [
        { key: 'path', label: 'Path', width: 260 },
        { key: 'type', label: 'Type', width: 90 },
        { key: 'mimetype', label: 'Mimetype', width: 160 },
        { key: 'filename', label: 'Download', sortable: false, filterable: false, width: 120,
          render: (value, row) => {
              if (!row.base64) return 'N/A';
              const button = el('button', 'lk-table-button', 'Download');
              button.type = 'button';
              button.title = 'Download the file';
              button.addEventListener('click', () => downloadBase64File(row.mimetype, row.base64, value));
              return button;
          } },
    ],
    credentials: [
        { key: 'id', label: 'ID', width: 160 },
        { key: 'rpId', label: 'Relying party (rpID)', width: 160 },
        { key: 'userHandle', label: 'User handle', width: 140 },
        { key: 'privateKey', label: 'Private key', width: 220 },
        { key: 'publicKey', label: 'Public key', width: 220 },
    ],
};

const readData = (element) => {
    const script = element.nextElementSibling;
    if (!script || script.type !== 'application/json') return null;
    try {
        return JSON.parse(script.textContent);
    } catch (e) {
        return null;
    }
};

const setupTables = (root) => {
    root.querySelectorAll('vt-table[data-lk-table]:not([data-lk-ready])').forEach(table => {
        const columns = TABLES[table.dataset.lkTable];
        const rows = readData(table);
        if (!columns || !rows) return;
        table.dataset.lkReady = '';
        customElements.whenDefined('vt-table').then(() => {
            // Columns shown as they are: true / false / null styled (literal)
            table.columns = columns.map(column => (column.render || column.format ? column : { ...column, render: literalOr }));
            table.data = rows;
        });
    });
};

// ---- MISP export (#mispExportModal, tree/tree.html) ----

const setupMispExport = (root) => {
    const panel = root.querySelector('[data-lk-misp-export]:not([data-lk-ready])');
    if (!panel) return;
    panel.dataset.lkReady = '';
    const url = panel.dataset.lkMispExport;
    const viewer = panel.querySelector('vt-json');
    const status = panel.querySelector('.lk-misp-status');
    const copy = panel.querySelector('[data-lk-misp-copy]');
    const download = panel.querySelector('[data-lk-misp-download]');
    let text = null;
    const filename = `lookyloo-${panel.dataset.lkCapture}.misp.json`;
    const ready = (on) => { copy.disabled = !on; download.disabled = !on; };
    copy.addEventListener('click', () => text && copyWithFeedback(copy, text));
    download.addEventListener('click', () => text && downloadText(text, filename));

    const loading = panel.querySelector('[data-lk-misp-loading]');
    const size_line = panel.querySelector('[data-lk-misp-size-line]');
    const say = (message) => { status.textContent = message; status.hidden = false; };
    const load = async () => {
        ready(false);
        viewer.hidden = true;
        status.hidden = true;
        size_line.hidden = true;
        // The eyes while the export is generated (it can take a while on a big capture)
        loading.hidden = false;
        try {
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            text = await response.text();
            ready(true);
            const size = `${(text.length / 1048576).toFixed(1)} MiB`;
            panel.querySelector('[data-lk-misp-size]').textContent = size;
            size_line.hidden = false;
            if (text.length > MAX_JSON) {
                say(`The export (${size}) is too big to be shown here: download it.`);
                return;
            }
            await customElements.whenDefined('vt-json');
            viewer.content = text;
            viewer.hidden = false;
        } catch (error) {
            say(`The MISP export failed (${error.message}).`);
        } finally {
            loading.hidden = true;
        }
    };
    panel.querySelector('[data-lk-misp-reload]')?.addEventListener('click', load);
    // Loaded the first time the panel is shown (the menu entry opens #mispExportModal,
    // js/side_panel.js sends show.bs.modal), not with the capture page
    const modal = panel.closest('.modal');
    if (modal) {
        modal.addEventListener('show.bs.modal', () => { if (text === null) load(); });
    } else {
        load();
    }
};

// ---- Console messages: the log lines are in the <script type="application/json"> after <vt-log> ----

const setupLogs = (root) => {
    root.querySelectorAll('vt-log[data-lk-log]:not([data-lk-ready])').forEach(log => {
        const lines = readData(log);
        if (!Array.isArray(lines)) return;
        log.dataset.lkReady = '';
        customElements.whenDefined('vt-log').then(() => {
            log.content = lines.map(line => JSON.stringify(line)).join('\n');
        });
    });
};

// ---- Double-click on a value: copied (every panel of the side panel) ----

// The value under the mouse, from the innermost element (composedPath: also inside
// the vitrine components), or null for the controls (links, buttons, fields)
const valueAt = (path) => {
    const elements = path.filter(node => node instanceof Element);
    if (elements.some(node => node.matches('a, button, input, textarea, select, summary, label, [role="button"], [role="tab"]'))) return null;
    // A table cell first: the whole cell, even when the click is on a line of the JSON in it
    const cell = elements.find(node => node.matches('td[part~="cell"], [role="gridcell"]'));
    if (cell) {
        const json = cell.querySelector('vt-json');
        return json ? json.content : cell.textContent;
    }
    for (const node of elements) {
        // vt-log: one field, the time, or the message without its fields
        if (node.matches('.field-value, .field-key, .time')) return node.textContent;
        if (node.matches('.field')) return node.querySelector('.field-value')?.textContent ?? node.textContent;
        if (node.matches('.msg')) {
            return [...node.childNodes].filter(n => !(n instanceof Element && n.classList.contains('fields')))
                .map(n => n.textContent).join('');
        }
        // A JSON viewer: the line clicked
        if (node.matches('vt-json')) return null;
        // Our own markup: a fact, a file, an origin, a title...
        if (node.matches('dd, dt, .lk-file-name, .lk-origin-name, .lk-panel-title, .lk-misp-size, p, li, span, code, td, th')) {
            return node.textContent;
        }
        if (node.classList.contains('lk-panel') || node.id === 'lk-side-panel-body') return null;
    }
    return null;
};

// "Copied" next to the mouse for a moment
const copiedBubble = (doc, x, y, ok) => {
    const bubble = doc.createElement('div');
    bubble.className = `lk-copied-bubble${ok ? '' : ' is-failed'}`;
    bubble.textContent = ok ? 'Copied' : 'Copy failed';
    bubble.setAttribute('role', 'status');
    bubble.style.left = `${x}px`;
    bubble.style.top = `${y}px`;
    doc.body.appendChild(bubble);
    setTimeout(() => bubble.remove(), 1200);
};

function copyOnDoubleClick(doc = document) {
    copyHint(doc);
    doc.addEventListener('dblclick', (event) => {
        const path = event.composedPath();
        // Only in the panels (side panel, detached window, "Open as a page")
        if (!path.some(node => node instanceof Element && (node.classList.contains('lk-panel') || node.id === 'lk-side-panel-body'))) return;
        const raw = valueAt(path);
        const value = raw?.replace(/[\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '').trim();
        if (!value) return;
        // The word selected by the double-click is not what is copied: the whole value is
        doc.getSelection()?.removeAllRanges();
        const win = doc.defaultView || window;
        if (!win.navigator.clipboard) {
            copiedBubble(doc, event.clientX, event.clientY, false);
            return;
        }
        win.navigator.clipboard.writeText(value).then(
            () => copiedBubble(doc, event.clientX, event.clientY, true),
            () => copiedBubble(doc, event.clientX, event.clientY, false));
    });
}
// The mouse cursor stays the normal one; a small copy icon follows it over what a
// double-click copies (css/components/capture-panels.css, .lk-copy-hint)
function copyHint(doc) {
    const NS = 'http://www.w3.org/2000/svg';
    const hint = doc.createElement('span');
    hint.className = 'lk-copy-hint';
    hint.hidden = true;
    hint.setAttribute('aria-hidden', 'true');
    const svg = doc.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('width', '14');
    svg.setAttribute('height', '14');
    svg.setAttribute('fill', 'currentColor');
    const path = doc.createElementNS(NS, 'path');
    // Bootstrap Icons "copy"
    path.setAttribute('fill-rule', 'evenodd');
    path.setAttribute('d', 'M4 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1zM2 5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1h1v1a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h1v1z');
    svg.appendChild(path);
    hint.appendChild(svg);
    doc.body.appendChild(hint);
    let pending = null;
    doc.addEventListener('pointermove', (event) => {
        if (event.pointerType !== 'mouse') return;
        const path = event.composedPath();
        const x = event.clientX, y = event.clientY;
        if (pending) return;
        pending = (doc.defaultView || window).requestAnimationFrame(() => {
            pending = null;
            const inPanel = path.some(node => node instanceof Element && (node.classList.contains('lk-panel') || node.id === 'lk-side-panel-body'));
            const interactive = path.some(node => node instanceof Element && node.matches('a, button, input, select, textarea, summary, label, [role="button"], [role="tab"]'));
            const copyable = inPanel && !interactive && !!valueAt(path)?.trim();
            hint.hidden = !copyable;
            if (copyable) hint.style.transform = `translate(${x + 14}px, ${y + 16}px)`;
        });
    }, {passive: true});
    doc.addEventListener('pointerleave', () => { hint.hidden = true; });
    hint.style.left = '0';
    hint.style.top = '0';
}
window.copyOnDoubleClick = copyOnDoubleClick;   // detached windows (js/side_panel.js)
copyOnDoubleClick(document);

// ---- Parts of a panel loaded from another URL (the statistics in Capture details) ----

const setupRemoteParts = (root) => {
    root.querySelectorAll('[data-lk-remote-part]:not([data-lk-ready])').forEach(part => {
        part.dataset.lkReady = '';
        let loaded = false;
        const load = async () => {
            if (loaded) return;
            loaded = true;
            try {
                const response = await fetch(part.dataset.lkRemotePart);
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                // HTML rendered (and escaped) by Flask, like the panels themselves
                part.innerHTML = await response.text();
                setupCapturePanels(part);
            } catch (error) {
                part.textContent = `Could not be loaded (${error.message}).`;
                loaded = false;
            }
        };
        // In a panel written in the page: when it is shown (show.bs.modal, js/side_panel.js)
        const modal = part.closest('.modal');
        if (modal && !part.closest('.lk-side-panel-content')) {
            modal.addEventListener('show.bs.modal', load);
        } else {
            load();
        }
    });
};

// ---- Entry point ----

function setupCapturePanels(root = document) {
    setupRemoteParts(root);
    setupTables(root);
    setupLogs(root);
    setupMispExport(root);
    // Copy buttons of the panels (data-lk-copy-text)
    root.querySelectorAll('[data-lk-copy-text]:not([data-lk-ready])').forEach(button => {
        button.dataset.lkReady = '';
        button.addEventListener('click', () => copyWithFeedback(button, button.dataset.lkCopyText));
    });
}
window.setupCapturePanels = setupCapturePanels;
window.copyWithFeedback = copyWithFeedback;

// The "Open as a page" versions of the panels, and the panels already in the page
setupCapturePanels(document);
