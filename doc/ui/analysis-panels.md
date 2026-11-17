# Analysis panels (capture page)

The panels of the **Analysis** menu of the capture page, opened in the side
panel ([side-panel.md](side-panel.md)), styled like the Capture ones
([capture-panels.md](capture-panels.md)): `panel_header()` ("Analysis", title,
description), then the content, or `panel_empty()` when there is nothing.

## In this capture

Resources, IP addresses, Hostnames, URLs, Favicons, (Fuzzy) hashes types, Other
identifiers, Cloudflare name servers (`tree/modals/tree_*.html`). Each one is a
vitrine `<vt-table>` (filter row hidden at first, no row numbers, text wrapped, no copy / download / full
screen), sorted by the number of captures with the value.

- The rows come from `analysis_rows(kind, tree_uuid)` in
  `website/web/__init__.py`, rendered in a `<script type="application/json">`
  next to the table. Plain values only: the cells are built with DOM APIs
  (`TABLES` in `js/capture_panels.js`), nothing is HTML from the server.
- The value (IP, hostname, URL, hash, identifier, favicon, name servers) opens
  its details panel (`panelLink()`: `data-remote` + the details modal, opened in
  the side panel), the pivot to the other captures.
- **URLs in the capture**: the URL nodes with the value, each one shows its node
  in the tree (`LocateNode()`, js/tree_modals.js); folded when there are more
  than 3. `(embedded)` marks a resource found inside another one.
- Copy buttons next to every value (`withCopy()`, [capture-panels.md](capture-panels.md));
  a folded list (more than 3 URLs or hostnames) has a **copy all** button in
  its summary (one value per line).
- Resources: the type links to the resource itself (download), with a copy
  button. Favicons: the
  image, its Shodan MMH3 and SHA-512, a Download button in the look of the site buttons (`tableButton()`, styled inline: the cell is in the shadow DOM).

The old `/tables/<name>/<uuid>` endpoints of these tables are still there (API
users may call them).

## Third party reports

`tree/modals/modules.html`: one section per service that has something
(urlscan.io scan and verdict, Phishtank URLs and IPs, URLhaus, VirusTotal
vendors, Phishing Initiative tags), links open the report on the service. When
none has a result, or no service is configured, the panel says so ("No
report") instead of staying blank.

## Hashlookup hits

`tree/modals/hashlookup.html`: the resources of the capture known by CIRCL
hashlookup. Three `<vt-stats>` tiles (known resources, resources in the
capture, % known), then one section per hit (named after its file): every field
of its hashlookup entry as facts with copy buttons (the SHA-1 links to
hashlookup), the nested ones in a `<vt-json>`, and the URLs of the capture with
the file (a click shows the node in the tree, `data-lk-locate`; copy all).
"Hashlookup is not available" when the module is off or failed, "No hit" when
no resource is known. `hashlookup()` in `website/web/__init__.py` gives each
hit its URL nodes once, with their host node.

## Search events on MISP

`tree/modals/misp_lookup.html`, "MISP hits": the events of the MISP instance(s)
with values of the capture (URLs, hostnames, domains, IPs resolved at capture
time, CNAMEs and resources of the nodes up to the rendered page; the values of
the warning lists enabled on the MISP are skipped by MISP).

- The header shows the **MISP 3 logo** at the top left instead of the icon,
  with "Analysis · MISP hits" in small under it
  (`panel_header(logo=(light URL, dark URL, name))`, one image per theme). The
  logos are third party files: `install_misp_logo()` in `tools/3rdparty.py`
  downloads `app/webroot/img/misp-logo-horizontal.png` and
  `misp-logo-horizontal-light.png` of the MISP repository at a pinned commit of
  `3.0_wip` (`MISP_LOGO_COMMIT`), checks their SHA-256 (`MISP_LOGOS`) and puts
  them in `static/vendor/logos/` (not in the repository).
- `<vt-stats>` tiles: events, unpublished, high threat, values of the capture.
- The events as the **events index of MISP 3** shows them (`.lk-misp-*` in
  `css/components/capture-panels.css`, after `index-table.css`,
  `events-index-table.css`, `events-index-cards.css` and `org-tile.css` of MISP
  3.0_wip, on the `--lk-*` tokens): publish state, ID, title (link to MISP),
  creator org with its coloured tile and initials, markings (TLP / PAP, the tag
  colour as border and tint, `tlp:clear` grey, `amber+strict` as `amber*`),
  **Attribution** (galaxy clusters of actors, malware and tools, violet chips),
  **Behaviour** (ATT&CK techniques as their ID, `T1566.002`), **Classification**
  (the other tags, the tag colour on the left, namespace in grey); each lane
  shows its first tag(s) and "+N" opens the others (`data-lk-more`), as in MISP 3;
  number of attributes, threat level,
  date, last change ("16 min ago"), then **In this capture**: the values of the
  capture in the event, as attribute chips (a click shows the node in the tree,
  `data-lk-locate`; copy button). The table follows the width of the panel: a
  container query on `.lk-misp-table-wrap` hides the columns one by one when it
  gets narrow (date, attributes, threat, creator, behaviour, attribution, last
  change, classification, ID), the title, markings and values stay.
- `_misp_events()` in `website/web/__init__.py` gets the metadata of all the
  events in one request (`search(controller='events', metadata=True)`), splits
  the tags into the lanes of MISP 3 (`_misp_tag()`: markings, attribution,
  behaviour, classification; namespace / value; hex colour only, as it goes in a
  style attribute), formats the dates (`_misp_when()`) and maps each
  value to the host node that has it.
- Several MISP instances: the buttons `#mispSelector` (js/tree_modals.js) show
  one at a time.
- "MISP is not available" when no MISP is configured (or the user must log in),
  "No hit" when nothing is found.

## Historical lookups

`tree/modals/historical_lookups.html`: what CIRCL Passive DNS saw for the
hostnames of the redirect chain of the capture, one section per hostname with
its DataTable (`name="CIRCL_pdns_table"`, filled by `js/render_tables.js`;
"CIRCL Passive DNS has no record for this hostname." when it is empty). The
header links to the CIRCL Passive DNS service. Instead of a blank panel:
"Historical lookups are not available" when the CIRCLPDNS module is not
configured (it needs an account), "Unable to run the historical lookup" with
the error of the module (said in the panel, no longer flashed on the next page),
"No historical data" when the redirect chain has no hostname.
