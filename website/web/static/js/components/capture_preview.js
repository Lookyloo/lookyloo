"use strict";
// Capture preview: shown at the left of each capture in the capture lists
// (js/components/capture_list.js).
//
// The screenshot of the capture (its thumbnail), always blurred first: pages can
// show anything (porn, gore...). A click reveals it, another one blurs it again.
// When there is no screenshot (or no thumbnail URL), an identicon of the hostname
// takes its place, like the GitHub avatars: same site, same icon.
// Doc: doc/ui/capture-list.md

const LK_PREVIEW_SIZE = 5;   // cells per side

// 32-bit FNV-1a hash of a string
function lkPreviewHash(text) {
    let hash = 0x811c9dc5;
    for (let i = 0; i < text.length; i++) {
        hash ^= text.charCodeAt(i);
        hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash;
}

function lkPreviewHost(url) {
    try {
        return new URL(url).hostname;
    } catch {
        return '';
    }
}

// <svg> identicon of a hostname: the left half (3 columns) is drawn from the
// hash bits and mirrored on the right.
function lkIdenticon(seed) {
    const svgNS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('viewBox', `0 0 ${LK_PREVIEW_SIZE} ${LK_PREVIEW_SIZE}`);
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    svg.classList.add('lk-identicon');
    const hash = lkPreviewHash(seed);
    const half = Math.ceil(LK_PREVIEW_SIZE / 2);
    let bit = 0;
    for (let x = 0; x < half; x++) {
        for (let y = 0; y < LK_PREVIEW_SIZE; y++, bit++) {
            if (!((hash >>> bit) & 1)) {
                continue;
            }
            for (const column of new Set([x, LK_PREVIEW_SIZE - 1 - x])) {
                const cell = document.createElementNS(svgNS, 'rect');
                cell.setAttribute('x', column);
                cell.setAttribute('y', y);
                cell.setAttribute('width', 1);
                cell.setAttribute('height', 1);
                svg.appendChild(cell);
            }
        }
    }
    return {svg, hue: lkPreviewHash(`hue:${seed}`) % 360};
}

const LK_PLACEHOLDER_UUID = '00000000-0000-0000-0000-000000000000';
const LK_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// UUID of the capture, from its link (/tree/<uuid>); null if it is not one
function lkPreviewUuid(href) {
    const match = /\/tree\/([^/?#]+)/.exec(href || '');
    return match && LK_UUID.test(match[1]) ? match[1] : null;
}

// Element shown for a capture. capture: {url, finalUrl, href, thumbnail}
// thumbnail: URL of a thumbnail for the placeholder UUID (data-lk-thumbnail of the table)
function lkCapturePreview(capture) {
    const uuid = lkPreviewUuid(capture.href);
    if (!uuid || !capture.thumbnail || !capture.thumbnail.includes(LK_PLACEHOLDER_UUID)) {
        return lkIdenticonPreview(capture);
    }
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'lk-thumb is-blurred';
    button.setAttribute('aria-pressed', 'false');
    button.setAttribute('aria-label', 'Show the screenshot (still slightly blurred)');
    button.title = 'Show the screenshot (still slightly blurred)';
    const image = document.createElement('img');
    image.alt = '';
    image.loading = 'lazy';
    image.decoding = 'async';
    image.width = 128;
    image.height = 80;
    // No screenshot for this capture: the identicon instead
    image.addEventListener('error', () => button.replaceWith(lkIdenticonPreview(capture)), { once: true });
    image.src = capture.thumbnail.replace(LK_PLACEHOLDER_UUID, uuid);
    button.appendChild(image);
    // A click never shows the screenshot in the clear: it goes from strongly
    // blurred to lightly blurred (.is-peek: the layout and the colours, not the
    // details of an image), another click blurs it strongly again. The clear
    // screenshot is in the capture itself.
    button.addEventListener('click', () => {
        const blurred = button.classList.toggle('is-blurred');
        button.classList.toggle('is-peek', !blurred);
        button.setAttribute('aria-pressed', String(!blurred));
        const label = blurred ? 'Show the screenshot (still slightly blurred)'
            : 'Blurred on purpose: a captured page can be shocking. Open the capture to see it clearly. Click to blur it again.';
        button.setAttribute('aria-label', label);
        button.title = label;
    });
    return button;
}

// Identicon of the hostname of the page
function lkIdenticonPreview(capture) {
    const host = lkPreviewHost(capture.finalUrl || capture.url);
    const preview = document.createElement('span');
    preview.className = 'lk-capture-preview';
    if (!host) {
        preview.classList.add('is-empty');
        return preview;
    }
    const {svg, hue} = lkIdenticon(host);
    // Only the hue comes from the hostname, the tones are in the CSS (light / dark)
    preview.style.setProperty('--lk-preview-hue', hue);
    preview.title = host;
    preview.appendChild(svg);
    return preview;
}
