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
import '../vendor/vitrine/esm/vt-tags.js';

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

// ---- Copy buttons next to the values (every panel of the side panel) ----

// "Copied" over the button for a moment
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

const cleanValue = (value) => String(value ?? '').replace(/[\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '').trim();

// A small copy button (Bootstrap Icons "copy"). Styled inline as well: inside the
// vitrine tables it is in a shadow DOM that our stylesheets do not reach.
function copyButton(value, doc = document) {
    const NS = 'http://www.w3.org/2000/svg';
    const button = doc.createElement('button');
    button.type = 'button';
    button.className = 'lk-copy-btn';
    button.title = 'Copy';
    button.setAttribute('aria-label', 'Copy');
    Object.assign(button.style, {
        display: 'inline-flex', alignItems: 'center', verticalAlign: 'middle', flex: 'none',
        marginLeft: '0.3rem', padding: '2px', border: '0', borderRadius: '4px',
        background: 'transparent', color: 'inherit', opacity: '0.5', cursor: 'pointer', lineHeight: '0',
    });
    button.addEventListener('mouseenter', () => { button.style.opacity = '1'; });
    button.addEventListener('mouseleave', () => { button.style.opacity = '0.5'; });
    const svg = doc.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('width', '13');
    svg.setAttribute('height', '13');
    svg.setAttribute('fill', 'currentColor');
    svg.setAttribute('aria-hidden', 'true');
    const path = doc.createElementNS(NS, 'path');
    path.setAttribute('fill-rule', 'evenodd');
    path.setAttribute('d', 'M4 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1zM2 5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1h1v1a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h1v1z');
    svg.appendChild(path);
    button.appendChild(svg);
    button.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        const box = button.getBoundingClientRect();
        const win = button.ownerDocument.defaultView || window;
        const text = cleanValue(typeof value === 'function' ? value() : value);
        const done = (ok) => copiedBubble(button.ownerDocument, box.left + box.width / 2, box.top, ok);
        if (!win.navigator.clipboard || !text) { done(false); return; }
        win.navigator.clipboard.writeText(text).then(() => done(true), () => done(false));
    });
    return button;
}
window.copyButton = copyButton;

// A cell content (text or node) followed by its copy button
const withCopy = (content, value) => {
    if (value === null || value === undefined || value === '') return content;
    const wrap = el('span');
    wrap.append(content, copyButton(value));
    return wrap;
};
// Column helper: the value as it is (true / false / null styled), with a copy button
const copyText = (value) => withCopy(literalOr(value), typeof value === 'string' ? value : JSON.stringify(value));

// Our own markup: the facts, file names, origins and report values get a copy
// button (not the ones with a control or a copy button already)
const setupCopyButtons = (root) => {
    root.querySelectorAll('.lk-panel-facts dd, .lk-file-name, .lk-report-value, [data-lk-copy]').forEach(node => {
        if (node.dataset.lkCopyReady !== undefined) return;
        node.dataset.lkCopyReady = '';
        if (node.querySelector('button, input, select, textarea, form, vt-table, vt-json, vt-log, .lk-panel-tags, [data-lk-copy]')) return;
        const value = cleanValue(node.dataset.lkCopy ?? node.textContent);
        if (!value) return;
        const button = copyButton(value, node.ownerDocument);
        if (node.matches('a')) node.after(button); else node.appendChild(button);
    });
};

// A small button in a table cell, in the look of the site buttons (.btn-sm
// outline): styled inline, the cells are in the shadow DOM of the component;
// the --lk-* tokens cross it, so it follows the light / dark theme
const DOWNLOAD_ICON = 'M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708z';
const tableButton = (label, title, onClick, iconPath = DOWNLOAD_ICON) => {
    const NS = 'http://www.w3.org/2000/svg';
    const button = el('button', 'lk-table-button');
    button.type = 'button';
    button.title = title;
    Object.assign(button.style, {
        display: 'inline-flex', alignItems: 'center', gap: '0.35rem', padding: '0.2rem 0.6rem',
        border: '1px solid var(--lk-color-rule-strong)', borderRadius: 'var(--lk-radius-md, 6px)',
        background: 'var(--lk-color-surface)', color: 'var(--lk-color-ink)',
        font: 'inherit', fontSize: '0.8125rem', fontWeight: '500', lineHeight: '1.4', cursor: 'pointer',
        whiteSpace: 'nowrap',
    });
    const hover = (on) => {
        button.style.borderColor = on ? 'var(--lk-color-accent)' : 'var(--lk-color-rule-strong)';
        button.style.color = on ? 'var(--lk-color-accent)' : 'var(--lk-color-ink)';
    };
    button.addEventListener('mouseenter', () => hover(true));
    button.addEventListener('mouseleave', () => hover(false));
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('width', '13');
    svg.setAttribute('height', '13');
    svg.setAttribute('fill', 'currentColor');
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS(NS, 'path');
    path.setAttribute('d', iconPath);
    svg.appendChild(path);
    button.append(svg, label);
    button.addEventListener('click', onClick);
    return button;
};

// ---- MISP tags, drawn like MISP 3 (its events index): the tag split by
// misp_tag_view() / _misp_tag() of website/web/__init__.py ({name, namespace,
// value, lane, colour, clear}). Inline styles on the --lk-* tokens: the same in
// the light DOM and inside the vitrine tables (shadow DOM). The Jinja twin is
// macros/misp.html; the CSS twin .lk-misp-mk / .lk-misp-chip. ----
// The renderer is shared: js/components/misp_tag.js (lkMispTag)
const mispTag = (tag) => window.lkMispTag(tag);

// ---- A vitrine table whose selected rows are sent with its form
// (data-lk-form-select): each selected row gives a hidden field (row.field or the
// attribute value, row.value); the rows with "selected": true are selected at
// first; [data-lk-select-count] says how many. ----
const setupSelectForms = (root) => {
    root.querySelectorAll('vt-table[data-lk-form-select]:not([data-lk-select-ready])').forEach(table => {
        const form = table.closest('form');
        if (!form) return;
        table.dataset.lkSelectReady = '';
        const count = form.querySelector('[data-lk-select-count]');
        const submit = form.querySelector('button[type="submit"]');
        const extra = () => (form.querySelector('textarea[name="user_urls"]')?.value || '').split('\n').filter(line => line.trim()).length;
        // [data-lk-select-chips]: the chosen rows above the table, as tags with a remove
        // button (row.chip: a MISP tag; else the text of the row)
        const chips = form.querySelector('[data-lk-select-chips]');
        const keyOf = (row) => row[table.getAttribute('row-key')];
        const drawChips = () => {
            if (!chips) return;
            const rows = table.selection || [];
            chips.replaceChildren();
            if (!rows.length) {
                chips.appendChild(el('span', 'lk-pivot-description', chips.dataset.lkEmpty || 'Nothing chosen.'));
                return;
            }
            rows.forEach(row => {
                const item = el('span', 'lk-chosen');
                item.appendChild(row.chip ? mispTag(row.chip) : el('span', null, row.url || keyOf(row)));
                const remove = el('button', 'lk-chosen-remove');
                remove.type = 'button';
                remove.title = 'Remove';
                remove.setAttribute('aria-label', `Remove ${row.tag || row.url || keyOf(row)}`);
                remove.textContent = '×';
                remove.addEventListener('click', () => {
                    table.select((table.selectedKeys || []).filter(key => key !== keyOf(row)));
                    table.dispatchEvent(new CustomEvent('vt-select'));
                });
                item.appendChild(remove);
                chips.appendChild(item);
            });
        };
        const update = () => {
            drawChips();
            const n = (table.selection || []).length;
            const total = n + extra();
            const noun = table.dataset.lkSelectNoun || 'row';
            const plural = noun.endsWith('y') ? `${noun.slice(0, -1)}ies` : `${noun}s`;
            if (count) count.textContent = `${n} ${n === 1 ? noun : plural} chosen`;
            if (submit && table.dataset.lkSelectRequired !== undefined) submit.disabled = total === 0;
        };
        table.addEventListener('vt-select', update);
        form.addEventListener('input', update);
        // data-lk-no-select-all: each row is chosen one by one. vt-table has no option
        // for it: its "select all" boxes (header, groups) and its selection menu are
        // hidden in its shadow DOM, and Ctrl/⌘+A is stopped (not in its search field)
        if (table.dataset.lkNoSelectAll !== undefined) {
            customElements.whenDefined('vt-table').then(() => {
                if (!table.shadowRoot) return;
                const style = document.createElement('style');
                style.textContent = 'thead .tb-check, .tb-group-inner .tb-check, .tb-select-more { display: none !important; }';
                table.shadowRoot.appendChild(style);
            });
            table.addEventListener('keydown', (event) => {
                const inField = event.composedPath()[0]?.matches?.('input, textarea');
                if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'a' && !inField) {
                    event.stopPropagation();
                    event.preventDefault();
                }
            }, true);
        }
        customElements.whenDefined('vt-table').then(() => {
            // After setupTables gave the data
            requestAnimationFrame(() => {
                const keys = (table.data || []).filter(row => row.selected).map(row => row[table.getAttribute('row-key')]);
                if (keys.length) table.select(keys);
                update();
            });
        });
        form.addEventListener('submit', () => {
            form.querySelectorAll('input[data-lk-from-table]').forEach(input => input.remove());
            (table.selection || []).forEach(row => {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = row.field || table.dataset.lkFormSelect;
                // The value of the row, or its key (the categories: the machinetag)
                input.value = row.value ?? row[table.getAttribute('row-key')];
                input.dataset.lkFromTable = '';
                form.appendChild(input);
            });
        });
    });
};

// ---- Analysis > In this capture (tree/modals/tree_*.html) ----

// Shows the node in the tree (js/tree_modals.js, LocateNode), from the side panel
// or a detached window
const locateNode = (hostnode) => {
    const page = typeof capturePage === 'function' ? capturePage() : window;
    (page?.LocateNode || window.LocateNode)?.(hostnode);
};

// The URLs of the capture with the value, each one shows its node in the tree;
// folded when there are more than 3
const nodesCell = (nodes) => {
    if (!Array.isArray(nodes) || !nodes.length) return '';
    const list = el('ul', 'lk-node-list');
    nodes.forEach(node => {
        const item = el('li');
        const button = el('a', 'lk-table-link', node.url);
        button.href = '#';
        button.setAttribute('role', 'button');
        button.title = 'Show the node in the tree';
        button.addEventListener('click', (event) => { event.preventDefault(); locateNode(node.hostnode); });
        item.append(button, copyButton(node.url));
        if (node.embedded) item.append(' ', el('em', null, '(embedded)'));
        list.appendChild(item);
    });
    if (nodes.length <= 3) return list;
    const details = el('details');
    const summary = el('summary', null, `${nodes.length} URLs`);
    // Copy all the URLs at once (one per line)
    const all = copyButton(() => nodes.map(node => node.url).join('\n'));
    all.title = 'Copy all the URLs';
    all.setAttribute('aria-label', 'Copy all the URLs');
    summary.appendChild(all);
    details.append(summary, list);
    return details;
};
// Text of the nodes for the filter of the column
const nodesText = (nodes) => (Array.isArray(nodes) ? nodes.map(node => node.url).join(' ') : '');

const capturesColumn = { key: 'captures', label: 'Captures', type: 'number', width: 110 };
// An IP with its flag and geolocation card (js/components/ip_geo.js), when enabled
const geoIp = (node, ip) => (window.lkIpGeo ? window.lkIpGeo.decorate(node, ip) : node);

const TABLES = {
    // Actions > Subsequent captures
    subsequent: [
        { key: 'url', label: 'URL', render: copyText },
        { key: 'source', label: 'Found', width: 200 },
    ],
    // Actions > Manage categories: the machinetag as a MISP tag
    categories: [
        { key: 'tag', label: 'Category', width: 280, format: (value) => value, render: (value, row) => mispTag(row.chip) },
        { key: 'type', label: 'Type', hidden: true },
        { key: 'description', label: 'Meaning' },
    ],
    urls: [
        capturesColumn,
        { key: 'url', label: 'URL', render: (value, row) => withCopy(panelLink(value, 'urlDetailsModal', row.detail), value) },
    ],
    hostnames: [
        capturesColumn,
        { key: 'hostname', label: 'Hostname', width: 220, render: (value, row) => withCopy(panelLink(value, 'hostnameDetailsModal', row.detail), value) },
        { key: 'ip', label: 'IP', width: 180, render: (value, row) => (row.ip_detail ? geoIp(withCopy(panelLink(value, 'ipDetailsModal', row.ip_detail), value), value) : value) },
        { key: 'nodes', label: 'URLs in the capture', width: 380, sortable: false, format: nodesText, render: nodesCell },
    ],
    ips: [
        capturesColumn,
        { key: 'ip', label: 'IP', width: 180, render: (value, row) => geoIp(withCopy(panelLink(value, 'ipDetailsModal', row.detail), value), value) },
        { key: 'hostname', label: 'Hostname', width: 220, render: (value, row) => withCopy(panelLink(value, 'hostnameDetailsModal', row.hostname_detail), value) },
        { key: 'nodes', label: 'URLs with the IP in the capture', width: 380, sortable: false, format: nodesText, render: nodesCell },
    ],
    body_hashes: [
        capturesColumn,
        { key: 'mimetype', label: 'Type', width: 170,
          render: (value, row) => {
              const wrap = el('span');
              const link = el('a', 'lk-table-link', value || row.generic);
              link.href = row.resource;
              link.title = 'Download the resource';
              wrap.append(link, copyButton(value || row.generic));
              return wrap;
          } },
        { key: 'nodes', label: 'URLs in the capture', width: 380, sortable: false, format: nodesText, render: nodesCell },
        { key: 'sha512', label: 'SHA-512', width: 260, render: (value, row) => withCopy(panelLink(value, 'bodyHashDetailsModal', row.detail), value) },
    ],
    favicons: [
        capturesColumn,
        { key: 'favicon', label: 'Favicon', width: 110, sortable: false, filterable: false,
          render: (value, row) => {
              const link = panelLink('', 'faviconDetailsModal', row.detail);
              link.title = 'Other captures with this favicon';
              const img = el('img');
              img.src = `data:${row.mimetype};base64,${value}`;
              img.alt = 'Favicon';
              img.width = 32;
              img.height = 32;
              link.appendChild(img);
              return link;
          } },
        { key: 'mmh3', label: 'Shodan MMH3', width: 160, render: (value) => withCopy(String(value), String(value)) },
        { key: 'sha512', label: 'SHA-512', render: (value, row) => withCopy(panelLink(value, 'faviconDetailsModal', row.detail), value) },
        { key: 'mimetype', label: 'Download', width: 120, sortable: false, filterable: false,
          render: (value, row) => {
              return tableButton('Download', 'Download the favicon', () => downloadBase64File(value, row.favicon, 'favicon.ico'));
          } },
    ],
    hashes_types: [
        capturesColumn,
        { key: 'type', label: 'Hash type', width: 160 },
        { key: 'hash', label: 'Hash', render: (value, row) => withCopy(panelLink(value, 'captureHashesTypesDetailsModal', row.detail), value) },
    ],
    identifiers: [
        capturesColumn,
        { key: 'type', label: 'Type', width: 160 },
        { key: 'identifier', label: 'Identifier', render: (value, row) => withCopy(panelLink(value, 'identifierDetailsModal', row.detail), value) },
    ],
    cloudflare_ns: [
        capturesColumn,
        { key: 'ns', label: 'Name servers', width: 240, render: (value, row) => withCopy(panelLink(value, 'cloudflareNSDetailsModal', row.detail), value) },
        { key: 'hostnames', label: 'Hostnames of the capture', sortable: false,
          format: (value) => (Array.isArray(value) ? value.join(' ') : ''),
          render: (value) => {
              const list = el('ul', 'lk-node-list');
              (value || []).forEach(hostname => { const item = el('li', null, hostname); item.appendChild(copyButton(hostname)); list.appendChild(item); });
              if ((value || []).length <= 3) return list;
              const details = el('details');
              const summary = el('summary', null, `${value.length} hostnames`);
              const all = copyButton(() => value.join('\n'));
              all.title = 'Copy all the hostnames';
              summary.appendChild(all);
              details.append(summary, list);
              return details;
          } },
    ],
    cookies: [
        { key: 'frequency', label: 'Captures', type: 'number', width: 150 },
        { key: 'name', label: 'Name', width: 180,
          render: (value, row) => withCopy(row.detail ? panelLink(value, 'cookieNameModal', row.detail) : value, value) },
        { key: 'value', label: 'Value', width: 280, render: (value) => withCopy(jsonOrText(value), value) },
        { key: 'domain', label: 'Domain', width: 160, render: copyText },
        { key: 'partition', label: 'CHIPS', width: 160, render: literalsInText },
        { key: 'expires', label: 'Expires', type: 'date', width: 200,
          format: (value) => (value > 0 ? datetime(value) : 'Session') },
        { key: 'path', label: 'Path', width: 90 },
        { key: 'httpOnly', label: 'HTTP only', ...yesNo },
        { key: 'secure', label: 'Secure', ...yesNo },
        { key: 'sameSite', label: 'Same site', width: 100 },
    ],
    local_storage: [
        { key: 'name', label: 'Name', width: 220, render: copyText },
        { key: 'value', label: 'Value', render: (value) => withCopy(jsonOrText(value), value) },
    ],
    opfs: [
        { key: 'path', label: 'Path', width: 260, render: copyText },
        { key: 'type', label: 'Type', width: 90 },
        { key: 'mimetype', label: 'Mimetype', width: 160 },
        { key: 'filename', label: 'Download', sortable: false, filterable: false, width: 120,
          render: (value, row) => {
              if (!row.base64) return 'N/A';
              return tableButton('Download', 'Download the file', () => downloadBase64File(row.mimetype, row.base64, value));
          } },
    ],
    credentials: [
        { key: 'id', label: 'ID', width: 160, render: copyText },
        { key: 'rpId', label: 'Relying party (rpID)', width: 160, render: copyText },
        { key: 'userHandle', label: 'User handle', width: 140, render: copyText },
        { key: 'privateKey', label: 'Private key', width: 220, render: copyText },
        { key: 'publicKey', label: 'Public key', width: 220, render: copyText },
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
    setupCopyButtons(root);
    setupSelectForms(root);
    // A vitrine <vt-tags> sent as one field per tag (data-lk-tags-field="<name>"): the
    // routes read a list (request.form.getlist), vt-tags submits one JSON value
    root.querySelectorAll('vt-tags[data-lk-tags-field]:not([data-lk-ready])').forEach(field => {
        field.dataset.lkReady = '';
        // The tags of the field, of the suggestions and of the browse panel drawn as MISP
        // tags (vitrine gives no part for the options, nor a way to split a label): a
        // stylesheet in the shadow DOM of the component, and an observer that rebuilds
        // each label as MISP shows it (namespace small and grey, value; TLP / PAP as
        // markings) with its full name as title. The tags come from the JSON of the field
        // (misp_tag_option: value, label, kind = lane).
        let byLabel = new Map();
        try {
            const data = JSON.parse(field.querySelector('script[type="application/json"]')?.textContent || '{}');
            byLabel = new Map((data.options || []).map(option => [option.label, option]));
        } catch (e) { /* no options: nothing to rebuild */ }
        const rebuild = (label) => {
            if (label.dataset.lkMisp !== undefined) return;
            const option = byLabel.get(label.textContent.trim());
            if (!option) return;
            label.dataset.lkMisp = '';
            label.title = option.value;
            const [namespace, ...rest] = option.label.split(' ');
            const marking = (option.kind || '').startsWith('markings');
            label.classList.add(marking ? 'is-marking' : 'is-tag');
            if (option.kind === 'markings-clear') label.classList.add('is-clear');
            if (!rest.length) return;
            const small = document.createElement('small');
            small.textContent = namespace;
            const value = document.createElement(marking ? 'b' : 'span');
            value.textContent = rest.join(' ');
            label.replaceChildren(small, value);
        };
        customElements.whenDefined('vt-tags').then(() => {
            const shadow = field.shadowRoot;
            if (!shadow || shadow.querySelector('style[data-lk-misp]')) return;
            const style = document.createElement('style');
            style.dataset.lkMisp = '';
            style.textContent = `
                .swatch, .tag.colored::before { display: none; }
                .option-label, .tag-label { display: inline-flex; align-items: baseline; gap: 4px; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
                .option-label {
                    align-self: flex-start; width: fit-content; max-width: 100%; height: 20px; align-items: center;
                    padding: 0 7px 0 6px; border: 1px solid var(--lk-color-rule); border-radius: 5px;
                    border-left: 3px solid var(--_tag-color, var(--lk-color-rule)); background: var(--lk-color-surface-2);
                    color: var(--lk-color-ink); font-size: 0.73rem;
                }
                .option-label small, .tag-label small { color: var(--lk-color-muted); font-size: 0.92em; font-weight: 600; }
                .option-label.is-marking {
                    height: 18px; padding: 0 5px; border: 1px solid var(--_tag-color, var(--lk-color-muted)); border-radius: 4px;
                    background: color-mix(in srgb, var(--_tag-color, var(--lk-color-muted)) 14%, var(--lk-color-surface)); font-size: 0.7rem;
                }
                .option-label.is-marking.is-clear { border-color: var(--lk-color-rule-strong); background: transparent; }
                .option-label b, .tag-label b { font-weight: 700; }
                .option-description { font-family: var(--lk-font-mono); font-size: 0.68rem; color: var(--lk-color-muted); }
                .browse-group { grid-template-columns: repeat(4, minmax(0, 1fr)); }
                .browse-option { align-items: center; gap: 8px; min-width: 0; }`;
            shadow.appendChild(style);
            const scan = () => shadow.querySelectorAll('.option-label, .tag-label').forEach(rebuild);
            scan();
            new MutationObserver(scan).observe(shadow, {childList: true, subtree: true});
        });
        // data-lk-browse-open: the "Browse all tags" panel open at first (no attribute
        // for it in vitrine: its button is pressed once the component is drawn)
        if (field.dataset.lkBrowseOpen !== undefined) {
            customElements.whenDefined('vt-tags').then(() => requestAnimationFrame(() => {
                const button = field.shadowRoot?.querySelector('[part~="browse-button"]');
                if (button && button.getAttribute('aria-pressed') !== 'true') button.click();
            }));
        }
        const form = field.closest('form');
        form?.addEventListener('submit', () => {
            form.querySelectorAll('input[data-lk-from-tags]').forEach(input => input.remove());
            [].concat(field.value || []).forEach(value => {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = field.dataset.lkTagsField;
                input.value = typeof value === 'object' ? value.value : value;
                input.dataset.lkFromTags = '';
                form.appendChild(input);
            });
        });
    });
    // Actions > Push to MISP: "Push it anyway" enables the button when the capture is
    // already on the MISP
    root.querySelectorAll('form[data-lk-misp-push] [data-lk-force-push]:not([data-lk-ready])').forEach(box => {
        box.dataset.lkReady = '';
        const submit = box.form?.querySelector('button[type="submit"]');
        box.addEventListener('change', () => { if (submit) submit.disabled = !box.checked; });
    });
    // "+N" of a list of tags (MISP hits): shows / hides the others
    root.querySelectorAll('[data-lk-more]:not([data-lk-ready])').forEach(button => {
        button.dataset.lkReady = '';
        const rest = button.previousElementSibling;
        const count = button.textContent;
        button.addEventListener('click', () => {
            const open = rest.hidden;
            rest.hidden = !open;
            button.closest('.lk-misp-ctx')?.classList.toggle('is-open', open);
            button.setAttribute('aria-expanded', String(open));
            button.textContent = open ? 'Less' : count;
        });
    });
    // Links that show a node in the tree (data-lk-locate: its host node)
    root.querySelectorAll('[data-lk-locate]:not([data-lk-ready])').forEach(link => {
        link.dataset.lkReady = '';
        link.addEventListener('click', (event) => { event.preventDefault(); locateNode(link.dataset.lkLocate); });
    });
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
