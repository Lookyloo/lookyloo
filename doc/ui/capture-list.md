# Capture list

The recent captures tables (`#IndexTable`): home page (`home/home.html`) and
recent / hidden / per category captures (`home/index.html`).

One row per capture: preview, title (link to the capture), initial URL with a
copy button, then either "No redirect" or the hostname trail
(`google.be › www.google.be › www.google.com`, an "Unencrypted hop" warning if
one URL is `http://`), and a folded redirect chain with a copy button per step
and the link to download the redirects. The time column shows "2 hours ago"
over the date and time, in the browser time zone, and a **View capture** button
at the bottom right of the row.

On phones the table becomes a list of blocks: the time goes on its own line
under the capture, and the button moves under the preview, on the left
(`.lk-capture-view-side`), so it never covers the text.

## Front-end only

The rows are built in the browser, from the JSON returned by
`POST /tables/indexTable/` (`post_table()` in `website/web/__init__.py`), which
is not changed. Its `page.display` and `redirects.display` fields are HTML
rendered and escaped by Flask: `js/components/capture_list.js` parses them with
`DOMParser` (inert) to read the title, the URLs, the capture link and the
download link, then builds the row with DOM APIs (`textContent`, attributes).
Nothing else is shown: no category, no error flag, as the JSON does not have
them. The screenshot comes from the existing `thumbnail` route.

Search and paging stay server-side; the render function gives DataTables the
`filter` value of the JSON for the search.

## Files

| File | Role |
|------|------|
| `static/js/components/capture_list.js` | `lkIndexColumns(table)`: the DataTables columns of `#IndexTable`, row and time cells |
| `static/css/components/capture-list.css` | Table and row look |
| `static/js/components/capture_preview.js` | `lkCapturePreview(capture)`: the blurred screenshot (or identicon) at the left of a row |
| `static/css/components/capture-preview.css` | Its look |

The table needs `class="table lk-capture-table"` and
`data-lk-icons="{{ url_for('bootstrap.static', filename='icons/bootstrap-icons.svg') }}"`
(Bootstrap Icons sprite used by the row icons). `js/render_tables.js` uses
`lkIndexColumns()` when it is loaded (pages extending `layouts/page.html`),
the previous three columns otherwise.

## Preview: blurred screenshot

Each row shows the screenshot of the capture (its thumbnail, `thumbnail` route,
256 px wide, loaded lazily), **always blurred first**: a captured page can show
anything. A click reveals it, another one blurs it again (`aria-pressed`).

The table gives the thumbnail URL for a placeholder UUID
(`data-lk-thumbnail="{{ url_for('thumbnail', tree_uuid='00000000-0000-0000-0000-000000000000', width=256) }}"`);
`js/components/capture_preview.js` puts the UUID of the capture there, taken
from its link and checked against the UUID format.

When a capture has no screenshot (the thumbnail does not load), an identicon
takes its place: a 5×5 symmetric pattern and a hue computed from the hostname
of the final page, like the GitHub avatars. Same site, same icon.

## Home page: compact list

On the home page the same table has `data-lk-compact`: `js/render_tables.js`
removes every DataTables control (`layout` with all positions set to `null`):
the 10 latest captures, no paging, no "per page", no search. A "See all
captures" button under the list (and the link next to the title) opens the
full list (route `index`).
