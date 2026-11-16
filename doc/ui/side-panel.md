# Side panel of the capture page

The panels of the capture menus (Capture, Analysis, Actions, Download, Admin)
and the panels opened from inside them (other occurrences of a hostname, a
favicon, an IP…) no longer open as modals over the tree: they open as **tabs in
a panel at the right of the tree**, like the tabs of a browser. The tree stays
visible and usable on the left.

Files: `templates/tree/side_panel.html`, `static/js/side_panel.js`,
`static/css/components/side-panel.css`. The hostname pop-up (a click on a node)
is not concerned yet.

## How it works

The panels are still written as Bootstrap modals in `tree/tree.html`, with the
same IDs and `data-remote`. `side_panel.js` listens to the clicks on anything
that would open one of them (`data-bs-toggle="modal"`, on `window`, capture
phase, before Bootstrap) and opens a tab instead:

- **Remote panels** (the opener has `data-remote`): the tab fetches its own copy
  of the content and sets it up like the modal loader of `js/tree_modals.js`
  (`renderTables`, `submitPandoraListener`, `mispSelector`, `downloadSvg`). So
  two hostnames, two favicons… can be open at the same time. Opening the same
  panel with the same URL again goes back to its tab and reloads it.
- **Panels written in the page** (details, screenshot, visibility, push, mail,
  monitoring): their `.modal-body` and `.modal-footer` are moved into the tab,
  and back into the modal when the tab is closed. `show.bs.modal`,
  `shown.bs.modal` and `hidden.bs.modal` are sent on the modal as Bootstrap
  would. One tab each.
- Only the content of the **current tab** is in the page; the others are kept
  aside with their state. The IDs the tables rely on (`render_tables.js`
  binds by ID) stay unique.
- `KEPT_AS_MODALS` (empty for now): IDs of real dialogs that stay Bootstrap modals.

## Using it

- **Tabs**: click to show, `×` or middle click to close; the title of a panel
  opened from inside another one ends with the value clicked
  (`Other occurrences of the hostname: fonts.gstatic.com`).
- **Width**: drag the left edge of the panel (or focus it and use ← / →). Each
  tab has its own width, remembered per kind of panel in `localStorage`
  (`lk-side-panel-width|<modal id>`). Between 320 px and the window minus 240 px.
- **Detach** (`box-arrow-up-right` button): the current tab opens in its own
  window, with the stylesheets of the page; it stays in the tab bar, in
  italics (a click focuses the window). Links that open panels inside that
  window open tabs on the capture page. Closing the window (or its Close button)
  closes the tab; closing the capture page closes the windows. Bootstrap
  JavaScript is not loaded in the window: tooltips and dropdowns inside a
  detached panel do not work.
- **Close all** (`×` of the bar), **Esc** closes the current tab (not while
  typing in a field).

## Around the panel

`--lk-side-panel-space` (on `<html>`) is the width the panel takes: the tree
controls and the legend move left of it, the blue edge glow of the drag stops
at it, and Center (`js/tree.js`, `centerOnRoot`) centres the first node in the
space left. Phones: the panel takes the whole width, no resize.
