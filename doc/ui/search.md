# Search

Route `search` (`/search`), template `home/search.html`, styles
`static/css/search.css`, script `static/js/search.js`.

One card per kind of search: URL part, IP address, resource, cookie name,
favicon hash, favicon file. The server uses the first field filled
(`search()` in `website/web/__init__.py`, not changed), so the page makes it
explicit: **as soon as a field is filled, the other ones are disabled and
greyed out**, and the note above the fields says which one is used. Emptied,
they all come back. A click on a greyed field puts the focus back on the
filled one.

Field names and the backend are unchanged.
