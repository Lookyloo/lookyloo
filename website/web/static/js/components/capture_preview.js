"use strict";
// Capture preview: the square shown at the left of each capture in the capture
// lists (js/components/capture_list.js).
//
// TEMPORARY: until the screenshots are shown (blurred, click to reveal), the
// preview is an identicon, like the GitHub avatars: a 5x5 symmetric pattern and a
// colour computed from the hostname of the page. Same site, same icon, so the
// list can be scanned at a glance. Nothing is requested from the server.
//
// To switch to the screenshots, only this file and css/components/capture-preview.css
// change: lkCapturePreview() receives the capture (uuid, url, ...) and returns the
// element to show. Doc: doc/ui/capture-list.md

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

// Element shown for a capture. capture: {uuid, url, finalUrl, title}
function lkCapturePreview(capture) {
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
