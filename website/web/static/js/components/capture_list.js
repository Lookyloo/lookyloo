"use strict";
// Capture list: one row per capture (preview, title, URL, redirect trail, time)
// for the recent captures tables (#IndexTable, home/index.html and home/home.html).
//
// Front-end only: the rows are built from the JSON already returned by
// POST /tables/indexTable/ (post_table in website/web/__init__.py), unchanged.
// Its fields are HTML fragments rendered and escaped by Flask; they are parsed
// with DOMParser (inert: no script runs, nothing is loaded) and every value is
// written back with textContent / attributes, never as HTML.
// Doc: doc/ui/capture-list.md

// Bootstrap Icons sprite (served by bootstrap-flask), set on the table: data-lk-icons
function lkIcon(sprite, name) {
    const svgNS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('class', 'bi');
    svg.setAttribute('width', '1em');
    svg.setAttribute('height', '1em');
    svg.setAttribute('fill', 'currentColor');
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS(svgNS, 'use');
    use.setAttribute('href', `${sprite}#${name}`);
    svg.appendChild(use);
    return svg;
}

function lkElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) {
        element.className = className;
    }
    if (text !== undefined) {
        element.textContent = text;
    }
    return element;
}

function lkParseFragment(html) {
    return new DOMParser().parseFromString(html || '', 'text/html').body;
}

// One row of the indexTable JSON -> plain values
function lkParseIndexRow(row) {
    const page = lkParseFragment(row.page.display);
    const redirects = lkParseFragment(row.redirects.display);
    const titleElement = page.querySelector('span[title]');
    const link = page.querySelector('a[href]');
    const download = redirects.querySelector('a[href]');
    const url = page.querySelector('[data-copy]')?.dataset.copy || '';
    const hops = [...redirects.querySelectorAll('[data-copy]')].map(el => el.dataset.copy);
    return {
        title: titleElement ? titleElement.getAttribute('title') : '',
        href: link ? link.getAttribute('href') : null,
        url,
        hops: hops.length ? hops : (url ? [url] : []),
        redirectsHref: download ? download.getAttribute('href') : null,
        time: row.capture_time,
    };
}

function lkSplitUrl(url) {
    try {
        const parsed = new URL(url);
        return {
            scheme: `${parsed.protocol}//`,
            host: parsed.host,
            rest: url.slice(`${parsed.protocol}//${parsed.host}`.length),
            insecure: parsed.protocol === 'http:',
        };
    } catch {
        return {scheme: '', host: url, rest: '', insecure: false};
    }
}

// Copy button, same behaviour as the other ones (js-copy, js/generic.js)
function lkCopyButton(sprite, value, label = 'Copy the URL') {
    const button = lkElement('button', 'lk-copy js-copy');
    button.type = 'button';
    button.dataset.copy = value;
    button.dataset.bsToggle = 'tooltip';
    button.title = label;
    button.setAttribute('data-bs-original-title', label);
    button.setAttribute('aria-label', label);
    button.appendChild(lkIcon(sprite, 'copy'));
    return button;
}

// google.be › www.google.be › www.google.com (hosts only, consecutive duplicates
// merged, at most 4 shown)
function lkHopTrail(sprite, hops) {
    const hosts = hops.map(hop => lkSplitUrl(hop).host)
        .filter((host, i, all) => i === 0 || host !== all[i - 1]);
    const shown = hosts.length <= 4 ? hosts : [hosts[0], null, hosts.at(-2), hosts.at(-1)];
    const item = lkElement('li', 'lk-hop-trail');
    item.title = `${hops.length - 1} redirect${hops.length > 2 ? 's' : ''}`;
    item.appendChild(lkIcon(sprite, 'signpost-split'));
    shown.forEach((host, i) => {
        if (i) {
            const separator = lkElement('span', 'lk-hop-sep', '›');
            separator.setAttribute('aria-hidden', 'true');
            item.appendChild(separator);
        }
        if (host === null) {
            item.appendChild(lkElement('span', 'lk-hop-more', `+${hosts.length - 3}`));
        } else {
            item.appendChild(lkElement('span', `lk-hop${i === shown.length - 1 ? ' is-final' : ''}`, host));
        }
    });
    return item;
}

// Redirect chain, folded: one step per URL
function lkRoute(sprite, capture) {
    const details = lkElement('details', 'lk-route-details');
    const summary = lkElement('summary', null, 'Show the redirect chain ');
    summary.appendChild(lkElement('span', 'lk-route-count', `${capture.hops.length} steps`));
    details.appendChild(summary);
    const list = lkElement('ol', 'lk-route');
    let previousHost = null;
    capture.hops.forEach((hop, i) => {
        const last = i === capture.hops.length - 1;
        const parts = lkSplitUrl(hop);
        const step = lkElement('li', `lk-route-step${last ? ' is-last' : ''}`);
        const head = lkElement('div', 'lk-route-head');
        head.appendChild(lkElement('span', 'lk-route-label', i === 0 ? 'Start' : last ? 'Final page' : `Redirect ${i}`));
        if (i && parts.host !== previousHost) {
            head.appendChild(lkElement('span', 'lk-route-badge', 'new host'));
        }
        if (parts.insecure) {
            const badge = lkElement('span', 'lk-route-badge is-warning');
            badge.append(lkIcon(sprite, 'unlock'), ' HTTP');
            head.appendChild(badge);
        }
        const line = lkElement('div', 'lk-route-url');
        const text = lkElement('span', 'lk-route-text');
        text.title = hop;
        text.append(lkElement('span', 'lk-route-host', parts.scheme + parts.host),
                    lkElement('span', 'lk-route-path', parts.rest));
        line.append(text, lkCopyButton(sprite, hop));
        step.append(head, line);
        list.appendChild(step);
        previousHost = parts.host;
    });
    details.appendChild(list);
    if (capture.redirectsHref) {
        const download = lkElement('a', 'lk-route-download');
        download.href = capture.redirectsHref;
        download.append(lkIcon(sprite, 'download'), ' Download the redirects');
        details.appendChild(download);
    }
    return details;
}

// The capture cell: preview + title + URL + facts (+ redirect chain)
function lkCaptureCell(sprite, capture) {
    const wrapper = lkElement('div', 'lk-capture');
    wrapper.appendChild(lkCapturePreview({url: capture.url, finalUrl: capture.hops.at(-1),
                                          href: capture.href, thumbnail: capture.thumbnail}));

    const body = lkElement('div', 'lk-capture-body');
    const title = lkElement(capture.href ? 'a' : 'span', 'lk-capture-title', capture.title || 'No title');
    if (capture.href) {
        title.href = capture.href;
    }
    title.title = capture.title || '';
    body.appendChild(title);

    if (capture.url) {
        const url = lkElement('div', 'lk-capture-url');
        const text = lkElement('span', 'lk-capture-url-text', capture.url);
        text.title = capture.url;
        url.append(text, lkCopyButton(sprite, capture.url));
        body.appendChild(url);
    }

    const facts = lkElement('ul', 'lk-capture-facts');
    if (capture.hops.length > 1) {
        facts.appendChild(lkHopTrail(sprite, capture.hops));
        if (capture.hops.some(hop => lkSplitUrl(hop).insecure)) {
            const warning = lkElement('li', 'lk-capture-warning');
            warning.append(lkIcon(sprite, 'unlock'), ' Unencrypted hop');
            facts.appendChild(warning);
        }
    } else {
        const item = lkElement('li');
        item.append(lkIcon(sprite, 'check2'), ' No redirect');
        facts.appendChild(item);
    }
    body.appendChild(facts);
    if (capture.hops.length > 1) {
        body.appendChild(lkRoute(sprite, capture));
    }
    wrapper.appendChild(body);
    return wrapper;
}

// "2 hours ago" over the full date and time (local time zone)
const lkRelativeFormat = new Intl.RelativeTimeFormat('en', {numeric: 'auto'});
function lkRelativeTime(date) {
    const seconds = (date.getTime() - Date.now()) / 1000;
    const units = [['year', 31536000], ['month', 2592000], ['week', 604800],
                   ['day', 86400], ['hour', 3600], ['minute', 60]];
    for (const [unit, size] of units) {
        if (Math.abs(seconds) >= size) {
            return lkRelativeFormat.format(Math.round(seconds / size), unit);
        }
    }
    return 'just now';
}

function lkTimeCell(isoTime) {
    const date = new Date(isoTime);
    const time = lkElement('time', 'lk-relative-time');
    if (isNaN(date)) {
        time.textContent = isoTime;
        return time;
    }
    time.dateTime = isoTime;
    time.title = date.toString();
    const pad = value => String(value).padStart(2, '0');
    time.append(lkElement('span', null, lkRelativeTime(date)),
                lkElement('span', 'lk-absolute-time',
                          `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`));
    return time;
}

// DataTables columns of #IndexTable: [capture, time]. The cells are filled with
// DOM nodes in createdCell, the render only gives the text for search / sort.
function lkIndexColumns(table) {
    const sprite = table.dataset.lkIcons;
    // URL of a thumbnail, for a placeholder UUID (url_for in the template)
    const thumbnail = table.dataset.lkThumbnail || null;
    return [
        {
            data: null,
            render: (data, type, row) => type === 'display' ? '' : row.page.filter,
            createdCell: (cell, data, row) => cell.appendChild(lkCaptureCell(sprite, {...lkParseIndexRow(row), thumbnail})),
        },
        {
            data: 'capture_time',
            className: 'lk-capture-time',
            render: (data, type) => type === 'display' ? '' : data,
            createdCell: (cell, data) => cell.appendChild(lkTimeCell(data)),
        },
    ];
}
