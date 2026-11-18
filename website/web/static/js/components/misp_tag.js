"use strict";
// MISP tags drawn like MISP 3 (its events index), everywhere Lookyloo shows MISP tags
// or categories: the capture bar, the categories page, the category filter of the
// list of the captures, the panels (js/capture_panels.js: vitrine tables).
// - lkMispTag(tag): the element of a tag split like misp_tag_view() / _misp_tag() of
//   website/web/__init__.py ({name, namespace, value, lane, colour, clear}); inline
//   styles on the --lk-* tokens, so it is the same inside a shadow DOM;
// - lkMispTagView(name, colour): the same split in the browser (markings, galaxies,
//   other tags);
// - lkCategoryColour(name): the colour of a category of Lookyloo
//   (website/web/category_colours.json, given by layouts/main.html).
// The Jinja twin is macros/misp.html. Doc: doc/ui/misp-tags.md

const LK_MISP_GX_ICONS = {
    actor: 'M8 1a4 4 0 0 0-4 4v1H3v2h10V6h-1V5a4 4 0 0 0-4-4m-3 9a2 2 0 1 0 0 4 2 2 0 0 0 0-4m6 0a2 2 0 1 0 0 4 2 2 0 0 0 0-4',
    tool: 'M8 0 1.5 2.5v5C1.5 12 8 16 8 16s6.5-4 6.5-8.5v-5z',
};
function lkMispTag(tag) {
    if (!tag) return '';
    const node = document.createElement('span');
    node.title = tag.name;
    const base = {display: 'inline-flex', alignItems: 'center', gap: '4px', maxWidth: '100%', whiteSpace: 'nowrap',
                  color: 'var(--lk-color-ink)', verticalAlign: 'middle'};
    const small = (text) => {
        const part = document.createElement('small');
        part.textContent = text;
        Object.assign(part.style, {color: 'var(--lk-color-muted)', fontWeight: '600', fontSize: '0.92em'});
        return part;
    };
    if (tag.lane === 'markings') {
        node.className = 'lk-misp-mk';
        const colour = tag.clear ? 'var(--lk-color-rule-strong)' : (tag.colour || 'var(--lk-color-muted)');
        Object.assign(node.style, base, {alignItems: 'baseline', gap: '3px', height: '18px', lineHeight: '16px', padding: '0 5px',
            border: `1px solid ${colour}`, borderRadius: '4px', fontSize: '0.7rem',
            background: tag.clear ? 'transparent' : `color-mix(in srgb, ${colour} 14%, var(--lk-color-surface))`});
        const value = document.createElement('b');
        value.textContent = tag.value;
        node.append(small(tag.namespace), value);
        return node;
    }
    node.className = 'lk-misp-chip';
    Object.assign(node.style, base, {height: '20px', padding: '0 6px', borderRadius: '5px', fontSize: '0.73rem', lineHeight: '1',
        border: '1px solid var(--lk-color-rule)', background: 'var(--lk-color-surface-2)'});
    const text = document.createElement('span');
    Object.assign(text.style, {overflow: 'hidden', textOverflow: 'ellipsis', minWidth: '0'});
    if (tag.lane === 'attribution' || tag.lane === 'behaviour') {
        node.classList.add('is-gx');
        Object.assign(node.style, {background: 'var(--lk-misp-gx-wash)', borderColor: 'color-mix(in srgb, var(--lk-misp-gx) 60%, transparent)'});
        if (tag.lane === 'behaviour') {
            Object.assign(node.style, {fontFamily: 'var(--lk-font-mono)', fontSize: '0.69rem'});
        } else {
            node.style.fontWeight = '600';
            const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            svg.setAttribute('viewBox', '0 0 16 16');
            svg.setAttribute('width', '10');
            svg.setAttribute('height', '10');
            svg.setAttribute('fill', 'var(--lk-misp-gx-ink)');
            const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
            path.setAttribute('d', LK_MISP_GX_ICONS[tag.namespace] || LK_MISP_GX_ICONS.tool);
            svg.appendChild(path);
            node.appendChild(svg);
        }
        text.textContent = tag.value;
    } else {
        node.classList.add('is-tag');
        Object.assign(node.style, {borderLeft: `3px solid ${tag.colour || 'var(--lk-color-rule)'}`, paddingLeft: '5px'});
        if (tag.namespace) text.append(small(tag.namespace), ' ');
        text.append(tag.value);
    }
    node.appendChild(text);
    return node;
}
window.lkMispTag = lkMispTag;

function lkMispTagView(name, colour = null) {
    let namespace = '';
    let value = name;
    if (name.includes(':')) {
        [namespace, value] = [name.slice(0, name.indexOf(':')), name.slice(name.indexOf(':') + 1)];
        if (value.includes('=')) {
            [namespace, value] = [value.slice(0, value.indexOf('=')), value.slice(value.indexOf('=') + 1)];
        }
    }
    value = value.replace(/^"|"$/g, '');
    const lowered = name.toLowerCase();
    let lane = 'classification';
    if (lowered.startsWith('tlp:') || lowered.startsWith('pap:')) {
        lane = 'markings';
        namespace = namespace.toLowerCase();
        value = value.toLowerCase().replace('+strict', '*');
    } else if (lowered.startsWith('misp-galaxy:')) {
        const technique = /\bT\d{4}(?:\.\d{3})?\b/.exec(value);
        if (namespace.startsWith('mitre-') && technique) {
            [lane, namespace, value] = ['behaviour', value, technique[0]];
        } else {
            lane = 'attribution';
            namespace = ['threat-actor', 'groups', 'intrusion-set', 'mitre-intrusion-set'].includes(namespace) ? 'actor' : 'tool';
        }
    }
    return {name, namespace, value, lane, colour: /^#[0-9a-fA-F]{3,8}$/.test(colour || '') ? colour : null,
            clear: ['tlp:clear', 'tlp:white'].includes(lowered)};
}

let lkCategoryColours = null;
function lkCategoryColour(name) {
    if (lkCategoryColours === null) {
        try {
            lkCategoryColours = JSON.parse(document.getElementById('lk-category-colours')?.textContent || '{}');
        } catch (e) {
            lkCategoryColours = {};
        }
    }
    const entries = lkCategoryColours.entries || {};
    if (entries[name]) return entries[name];
    const match = /^[^:]+:([^=]+)=/.exec(name);
    return match ? (lkCategoryColours.predicates || {})[match[1]] || null : null;
}
