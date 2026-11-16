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

const yesNo = { type: 'boolean', align: 'center', width: 90 };

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
        { key: 'frequency', label: 'Captures', type: 'number', width: 110 },
        { key: 'name', label: 'Name', width: 180,
          render: (value, row) => (row.detail ? panelLink(value, 'cookieNameModal', row.detail) : value) },
        { key: 'value', label: 'Value', width: 240 },
        { key: 'domain', label: 'Domain', width: 160 },
        { key: 'partition', label: 'CHIPS', width: 140, format: (value) => value || '—' },
        { key: 'expires', label: 'Expires', type: 'date', width: 200,
          format: (value) => (value > 0 ? datetime(value) : 'Session') },
        { key: 'path', label: 'Path', width: 90 },
        { key: 'httpOnly', label: 'HTTP only', ...yesNo },
        { key: 'secure', label: 'Secure', ...yesNo },
        { key: 'sameSite', label: 'Same site', width: 100 },
    ],
    local_storage: [
        { key: 'name', label: 'Name', width: 220 },
        { key: 'value', label: 'Value' },
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
            table.columns = columns;
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

    const load = async () => {
        ready(false);
        viewer.hidden = true;
        status.hidden = false;
        status.textContent = 'Preparing the MISP export…';
        try {
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            text = await response.text();
            ready(true);
            const size = `${(text.length / 1048576).toFixed(1)} MiB`;
            panel.querySelector('[data-lk-misp-size]').textContent = size;
            if (text.length > MAX_JSON) {
                status.textContent = `The export (${size}) is too big to be shown here: download it.`;
                return;
            }
            status.hidden = true;
            await customElements.whenDefined('vt-json');
            viewer.content = text;
            viewer.hidden = false;
        } catch (error) {
            status.textContent = `The MISP export failed (${error.message}).`;
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

// ---- Entry point ----

function setupCapturePanels(root = document) {
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
