# Pivot pages

The pages that list the captures sharing one value: `templates/investigate/*`
(URL, hostname, domain, TLD, IP, resource, cookie name, HTTP headers hash,
favicon, capture hash, identifier, Cloudflare name servers). They all use the
same building blocks, `macros/investigate.html`, styled by
`static/css/components/pivot.css`:

- `pivot_header()`: a card with an icon (or the favicon / the mimetype icon),
  the kind of value, the value in monospace with a copy button, one sentence
  about the page, and the actions (Download, Shodan…).
- `pivot_section()`: a card with a title for the extra details (file of a
  resource, headers of a hash, CIRCL Passive DNS).
- `captures_section()`: the card around the captures table. The tables keep
  their ids and `data-*` attributes, read by `js/render_tables.js`.

Two ways to show a pivot page:

- **Standalone page** (`?from_popup=True`, what the search page and the "Open as
  a page" button open): `layouts/page.html`, so the site menu on top, and the
  breadcrumb `Home / Search / <kind> / <value>` (long values shortened there, in
  full in the card). No "Go back" button: the breadcrumb and the menu replace it.
- **Fragment in a capture modal** (no `from_popup`): only the cards, with an
  "Open as a page" button. `tree/tree.html` loads `pivot.css` for them.

Examples on a local instance (`<…>` from your own captures):

| Page | URL |
|------|-----|
| URL | `/urls/<URL in urlsafe base64>?from_popup=True` |
| Hostname | `/hostnames/<hostname>?from_popup=True` |
| Domain | `/domains/<domain>?from_popup=True` |
| TLD | `/tlds/<tld>?from_popup=True` |
| IP | `/ips/<ip>?from_popup=True` |
| Resource | `/body_hashes/<sha512>?from_popup=True` |
| Cookie name | `/cookies/<name>?from_popup=True` |
| HTTP headers hash | `/hhhdetails/<hhh>?from_popup=True` |
| Favicon | `/favicon_details/<sha512>?from_popup=True` |
| Capture hash | `/capture_hash_details/<hash type>/<hash>?from_popup=True` |
| Identifier | `/identifier_details/<type>/<identifier>?from_popup=True` |
| Cloudflare name servers | `/cloudflare_ns/<key>?from_popup=True` |

When the captures table comes back empty (value not indexed, captures
archived…), `static/js/components/pivot.js` hides it and shows a message with
links to **Search** and to the **list of the captures** (`.lk-pivot-empty` in
`captures_section()`). It listens to the DataTables `draw` events on the
document, so it also works in the capture modals.

## Captures table

The captures of a pivot page are shown like the list of the captures
([capture-list.md](capture-list.md)): blurred screenshot, title, URL with a copy
button, relative time and a **View capture** button. `lkPivotColumns()` in
`static/js/components/capture_list.js` builds the rows from the JSON of the
pivot tables (`capture_time`, `capture_title`, `landing_page`, and `hostnames`
for the Cloudflare one), unchanged; `render_tables.js` uses it through
`lkPivotColumnsOr()` (plain columns if the component is not loaded). Instead of
the redirects, a row says in how many nodes of the capture the value was found,
with a folded list of links to these nodes. The sprite and thumbnail URLs are
set on the wrapper by `captures_section()`. The capture tree page loads the
component too, for the pivot pages opened in its modals.

The rows show the same facts as the list of the captures (redirects, hop
trail, unencrypted hop, redirect chain with download): `post_table` adds the
redirect chain of each capture to the pivot rows (`redirects`, from
`_capture_redirects()`, read from the cache in valkey only, never builds a
tree). On top of that, "Found in N nodes" and the folded list of these nodes.

On the favicon page, the favicon can be clicked (`zoom=True` of
`pivot_header()`): `pivot.js` opens it in large in a `<dialog>` (same image, no
new request), closed by a click or Escape.

The total number of captures with the value is shown next to the title of the
captures (`[data-lk-count]`), from the DataTables `recordsTotal`.
