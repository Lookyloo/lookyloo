"use strict";
// Geolocation of the IPs (flag + card), everywhere an IP is shown:
// - in our markup: any element with data-lk-ip="<ip>" (pivot page of an IP, node
//   pages, panels loaded later: a MutationObserver finds them);
// - in the vitrine tables (shadow DOM): lkIpGeo.decorate(node, ip), called by the
//   renderers of js/capture_panels.js.
// A flag (emoji, from the ISO code) is put before the IP; the mouse or the focus on
// the IP opens a small card (world map with the country and its location, country,
// AS, organisation, databases) with a button to download the JSON. The data comes from /ip_geolookup (asked by batches,
// once per IP and page), which asks the mmdb-server of the instance (ip.circl.lu by
// default) from the server. Loaded only when it is enabled (layouts/main.html).
// Doc: doc/ui/ip-geolocation.md
(() => {
    // The tag of this script: URLs and SRI of D3, topojson-client and the world map
    const self = document.currentScript;
    const known = new Map();      // ip -> Promise of its info (or null)
    let batch = new Map();        // ip -> resolve, waiting for the next request
    let timer = null;

    const fetchBatch = () => {
        const waiting = batch;
        batch = new Map();
        timer = null;
        const params = new URLSearchParams();
        waiting.forEach((_, ip) => params.append('ip', ip));
        fetch(`/ip_geolookup?${params}`)
            .then(response => (response.ok ? response.json() : {}))
            .catch(() => ({}))
            .then(data => waiting.forEach((resolve, ip) => resolve(data && !data.error ? (data[ip] || null) : null)));
    };
    const info = (ip) => {
        if (!known.has(ip)) {
            known.set(ip, new Promise(resolve => {
                batch.set(ip, resolve);
                if (batch.size >= 50) {
                    clearTimeout(timer);
                    fetchBatch();
                } else if (!timer) {
                    timer = setTimeout(fetchBatch, 60);
                }
            }));
        }
        return known.get(ip);
    };

    // 🇺🇸 from "US": the two regional indicator symbols
    const flag = (iso) => (/^[A-Za-z]{2}$/.test(iso || '')
        ? String.fromCodePoint(...[...iso.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)) : '');

    // ---- World map: D3 + topojson-client + world-atlas (countries 110m), loaded the
    // first time a card has a location (static/vendor/, tools/3rdparty.py) ----
    let world = null;
    const loadScript = (src, sri) => new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = src;
        if (sri) script.integrity = sri;
        script.crossOrigin = 'anonymous';
        script.onload = resolve;
        script.onerror = reject;
        document.head.appendChild(script);
    });
    const loadWorld = () => {
        if (!world) {
            const data = self?.dataset || {};
            world = (window.d3 ? Promise.resolve() : loadScript(data.d3, data.d3Sri))
                .then(() => (window.topojson ? null : loadScript(data.topojson, data.topojsonSri)))
                .then(() => fetch(data.world, data.worldSri ? {integrity: data.worldSri} : {}))
                .then(response => response.json())
                .then(topology => window.topojson.feature(topology, topology.objects.countries))
                .catch(() => null);
        }
        return world;
    };
    // The countries, the one of the IP highlighted (world-atlas ids are the ISO
    // numeric codes), and a dot at its location (country average)
    const drawMap = (holder, data) => loadWorld().then(countries => {
        if (!countries || !window.d3 || !holder.isConnected) {
            holder.remove();
            return;
        }
        const width = 292, height = 150;
        const projection = d3.geoNaturalEarth1().fitSize([width, height], countries);
        const path = d3.geoPath(projection);
        const svg = d3.select(holder).append('svg')
            .attr('viewBox', `0 0 ${width} ${height}`).attr('role', 'img')
            .attr('aria-label', `World map: ${data.country || data.iso_code}`);
        svg.append('path').attr('class', 'lk-ip-map-sphere').attr('d', path({type: 'Sphere'}));
        const code = String(data.numeric || '').padStart(3, '0');
        svg.append('g').selectAll('path').data(countries.features).join('path')
            .attr('class', feature => (feature.id === code ? 'lk-ip-map-country is-here' : 'lk-ip-map-country'))
            .attr('d', path);
        const lat = Number(data.latitude), lon = Number(data.longitude);
        if (Number.isFinite(lat) && Number.isFinite(lon)) {
            const [x, y] = projection([lon, lat]);
            svg.append('circle').attr('class', 'lk-ip-map-halo').attr('cx', x).attr('cy', y).attr('r', 9);
            svg.append('circle').attr('class', 'lk-ip-map-dot').attr('cx', x).attr('cy', y).attr('r', 3.5);
        }
    });

    // ---- The card: one for the page, in the light DOM, placed next to the IP ----
    let card = null;
    let hideTimer = null;
    const el = (tag, className, text) => {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = String(text);
        return node;
    };
    const download = (data) => {
        const blob = new Blob([JSON.stringify(data.raw ?? data, null, 2)], {type: 'application/json'});
        const link = el('a');
        link.href = URL.createObjectURL(blob);
        link.download = `geolookup-${data.ip}.json`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    };
    const fill = (data, ip) => {
        card.replaceChildren();
        if (!data) {
            card.append(el('p', 'lk-ip-card-empty', `No geolocation for ${ip}.`));
            return;
        }
        const head = el('div', 'lk-ip-card-head');
        head.append(el('span', 'lk-ip-card-flag', flag(data.iso_code) || '🏳'));
        const title = el('div');
        title.append(el('strong', null, data.country || data.iso_code || 'Unknown country'), el('code', null, data.ip));
        head.appendChild(title);
        card.appendChild(head);
        const facts = el('dl', 'lk-ip-card-facts');
        const add = (label, value) => {
            if (value === undefined || value === null || value === '') return;
            facts.append(el('dt', null, label), el('dd', null, value));
        };
        add('Country', [data.iso_code, data.alpha3].filter(Boolean).join(' / '));
        add('AS', data.asn ? `AS${data.asn}` : null);
        add('Organisation', data.as_org);
        add('Location', data.latitude && data.longitude ? `${data.latitude}, ${data.longitude} (country average)` : null);
        (data.sources || []).forEach(source => add(source.source, `built ${source.built}`));
        if (data.numeric || data.latitude) {
            const map = el('div', 'lk-ip-map');
            card.appendChild(map);
            drawMap(map, data).then(() => { if (card.dataset.ip === ip) place(currentAnchor); });
        }
        card.appendChild(facts);
        const foot = el('div', 'lk-ip-card-foot');
        const button = el('button', 'btn btn-outline-secondary btn-sm', 'Download JSON');
        button.type = 'button';
        button.addEventListener('click', () => download(data));
        foot.append(el('span', 'lk-ip-card-source', 'mmdb-server'), button);
        card.appendChild(foot);
    };
    const place = (anchor) => {
        const box = anchor.getBoundingClientRect();
        const width = card.offsetWidth;
        const height = card.offsetHeight;
        let left = Math.min(box.left, window.innerWidth - width - 8);
        let top = box.bottom + 6;
        if (top + height > window.innerHeight - 8) top = Math.max(8, box.top - height - 6);
        card.style.left = `${Math.max(8, left)}px`;
        card.style.top = `${top}px`;
    };
    let currentAnchor = null;
    const show = (anchor, ip) => {
        clearTimeout(hideTimer);
        currentAnchor = anchor;
        if (card && !card.hidden && card.dataset.ip === ip) return;   // already open on it
        if (!card) {
            card = el('div', 'lk-ip-card');
            card.setAttribute('role', 'dialog');
            card.setAttribute('aria-label', 'Geolocation of the IP');
            card.addEventListener('mouseenter', () => clearTimeout(hideTimer));
            card.addEventListener('mouseleave', hide);
            document.body.appendChild(card);
        }
        card.dataset.ip = ip;
        card.replaceChildren(el('p', 'lk-ip-card-empty', 'Loading…'));
        card.hidden = false;
        place(anchor);
        info(ip).then(data => {
            if (card.dataset.ip !== ip || card.hidden) return;
            fill(data, ip);
            place(anchor);
        });
    };
    const hide = () => {
        clearTimeout(hideTimer);
        hideTimer = setTimeout(() => { if (card) card.hidden = true; }, 250);
    };
    document.addEventListener('keydown', (event) => { if (event.key === 'Escape' && card) card.hidden = true; });

    // ---- The flag and the events on an IP ----
    const decorate = (node, ip) => {
        if (!node || !ip || node.dataset.lkIpReady !== undefined) return node;
        node.dataset.lkIpReady = '';
        const mark = document.createElement('span');
        mark.className = 'lk-ip-flag';
        mark.setAttribute('aria-hidden', 'true');
        // Inline too: inside the vitrine tables our stylesheets do not apply
        Object.assign(mark.style, {display: 'inline-block', minWidth: '1.25em', marginRight: '0.3em', cursor: 'help'});
        node.prepend(mark);
        // A small spinner until the flag is there. Inline style and the Web Animations
        // API: inside the vitrine tables (shadow DOM) our stylesheets do not apply
        const spinner = document.createElement('span');
        spinner.className = 'lk-ip-spinner';
        Object.assign(spinner.style, {
            display: 'inline-block', width: '0.75em', height: '0.75em', verticalAlign: '-0.05em',
            border: '2px solid currentColor', borderRightColor: 'transparent', borderRadius: '50%', opacity: '0.5',
        });
        spinner.animate?.([{transform: 'rotate(0deg)'}, {transform: 'rotate(360deg)'}], {duration: 800, iterations: Infinity});
        mark.appendChild(spinner);
        mark.title = 'Geolocation…';
        info(ip).then(data => {
            mark.textContent = data ? flag(data.iso_code) : '';
            if (!data) mark.removeAttribute('title');
            if (data) mark.title = [data.country, data.asn ? `AS${data.asn} ${data.as_org || ''}` : ''].filter(Boolean).join(' · ');
        });
        // Only the IP (its link or text) and the flag open the card, not the copy
        // button next to them
        const onCopy = (event) => !!event.target.closest?.('.lk-copy-btn, .js-copy');
        node.addEventListener('mouseover', (event) => (onCopy(event) ? hide() : show(node, ip)));
        node.addEventListener('mouseleave', hide);
        node.addEventListener('focusin', (event) => { if (!onCopy(event)) show(node, ip); });
        node.addEventListener('focusout', hide);
        return node;
    };
    const scan = (root) => {
        if (!(root instanceof Element) && root !== document) return;
        if (root instanceof Element && root.matches('[data-lk-ip]')) decorate(root, root.dataset.lkIp);
        root.querySelectorAll?.('[data-lk-ip]').forEach(node => decorate(node, node.dataset.lkIp));
    };
    window.lkIpGeo = {decorate, info, flag};
    const start = () => {
        scan(document);
        new MutationObserver(records => records.forEach(record => record.addedNodes.forEach(scan)))
            .observe(document.body, {childList: true, subtree: true});
    };
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();
