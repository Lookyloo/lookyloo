// While a list of captures loads (the tables .lk-capture-table: #IndexTable of the home
// and Recent captures / Hidden, the captures of the pivot pages), placeholders in the
// shape of its rows: vitrine <vt-skeleton> (vendor/vitrine/, tools/3rdparty.py) for the
// preview, the title, the URL, the facts, the time and the button, the whole width of
// the table, one per row of the page (at most 10). The eyes of the logo stay over them
// (the processing indicator of DataTables, js/components/datatables.js). Loaded as a
// module by layouts/page.html. Doc: doc/ui/capture-list.md
import '../../vendor/vitrine/esm/vt-skeleton.js';

const bone = (shape, attrs = {}) => {
    const node = document.createElement('vt-skeleton');
    node.setAttribute('shape', shape);
    node.setAttribute('active', '');
    Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, value));
    // The colours of the site (light / dark)
    node.style.setProperty('--vt-skeleton-color', 'var(--lk-color-surface-2)');
    node.style.setProperty('--vt-skeleton-highlight', 'var(--lk-color-surface)');
    return node;
};

const row = (columns) => {
    const tr = document.createElement('tr');
    tr.className = 'lk-skeleton-row';
    tr.setAttribute('aria-hidden', 'true');
    const td = document.createElement('td');
    td.colSpan = columns;
    const line = document.createElement('div');
    line.className = 'lk-skeleton-capture';
    const text = document.createElement('div');
    text.className = 'lk-skeleton-text';
    text.append(bone('heading', {width: '55%'}), bone('text', {lines: '1', width: '40%'}), bone('text', {lines: '1', width: '30%'}));
    const side = document.createElement('div');
    side.className = 'lk-skeleton-side';
    side.append(bone('block', {width: '90px', height: '12px'}), bone('block', {width: '110px', height: '10px'}), bone('button', {width: '120px'}));
    line.append(bone('block', {width: '128px', height: '80px', radius: '8px'}), text, side);
    td.appendChild(line);
    tr.appendChild(td);
    return tr;
};

const show = (table, on) => {
    const body = table.tBodies[0] || table.appendChild(document.createElement('tbody'));
    body.querySelectorAll('.lk-skeleton-row').forEach(tr => tr.remove());
    body.classList.toggle('lk-skeleton-loading', on);
    if (!on) return;
    const api = window.DataTable?.isDataTable?.(table) ? new window.DataTable(table) : null;
    const count = Math.max(3, Math.min(10, api ? api.page.len() : 10));
    const columns = table.tHead?.rows[0]?.cells.length || 2;
    for (let i = 0; i < count; i++) body.appendChild(row(columns));
};

// Each list of captures: placeholders at once (before its first answer), then before each
// request (preXhr) until its rows are drawn (draw). The events are bound on the table
// itself (with DataTables 2 they do not reach the document).
const follow = (table) => {
    if (table.dataset.lkSkeleton !== undefined || !window.jQuery) return;
    table.dataset.lkSkeleton = '';
    if (!table.querySelector('tbody tr:not(.lk-skeleton-row)')) show(table, true);
    window.jQuery(table)
        .on('preXhr.dt', () => show(table, true))
        .on('draw.dt xhr.dt', () => show(table, false));
};
const scan = () => document.querySelectorAll('table.lk-capture-table').forEach(follow);
scan();
new MutationObserver(scan).observe(document.body, {childList: true, subtree: true});
