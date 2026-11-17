# Side panel of the capture page

The panels of the capture menus (Capture, Analysis, Actions, Download, Admin)
and the panels opened from inside them (other occurrences of a hostname, a
favicon, an IP…) no longer open as modals over the tree: they open as **tabs in
a panel at the right of the tree**, like the tabs of a browser. The tree stays
visible and usable on the left.

Files: `templates/tree/side_panel.html`, `static/js/side_panel.js`,
`static/css/components/side-panel.css`. The hostname pop-up (a click on a node)
opens here too, see below.

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

- **Tabs**: click to show, `×` or middle click to close, **drag a tab** along
  the bar to reorder (a blue line shows where it goes; pointer events, not
  HTML drag and drop), or Shift + ← / → on a focused tab; the title of a panel
  opened from inside another one ends with the value clicked
  (`Other occurrences of the hostname: fonts.gstatic.com`).
- **Width**: drag the left edge of the panel (or focus it and use ← / →). The
  edge has a visible grip in the middle (a small pill with two lines) and turns
  blue on hover. The handle (`.lk-side-panel-resize`, 12 px wide, half outside
  the panel) is above everything in the panel (`z-index`: the vitrine components
  have their own layers and used to cover it below the header), and a press on
  it never starts a drag of the tree.
  **One width for the whole panel**, the same for every tab (switching tabs
  never moves it), remembered in `localStorage` (`lk-side-panel-width`).
  Between 320 px and the window minus 240 px.
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
controls move left of it (the legend is at the bottom left), the blue edge glow of the drag stops
at it, and Center (`js/tree.js`, `centerOnRoot`) centres the first node in the
space left. Phones: the panel takes the whole width, no resize.

## Details of a node

A click on a node of the tree no longer opens a pop-up window: the details of
the node (`tree/hostname_popup.html`) open in a tab, `Node: <hostname>`, as a
whole page in a frame (`openPage()`, `window.lkSidePanel`); the eyes of the
logo cover the frame until the page is loaded (`.lk-side-panel-loading.is-over-page`). Frames are hidden,
not taken out of the page, when another tab is shown (they would reload).

- The node of the current tab is **selected in the tree**: outlined in blue
  with a glow (`g.node.is-selected`, `css/tree.css`) and scrolled to the middle
  of the space left of the panel (`window.lkTree.selectNode`, `js/tree.js`).
  Another tab, or no tab: the selection follows / is cleared. A node in a
  collapsed branch is not drawn: nothing to select.
- The page talks to the capture page through `capturePage()` (`js/generic.js`):
  `window.opener` in a pop-up window, `window.parent` in a tab ("Locate in
  tree", "open the capture in a new tab").
- **Detach** of a node tab: the page opens in its own window, like the former
  pop-up (`window.opener` works), and the tab is closed.
- Without the side panel script, `open_hostnode_popup()` still opens the pop-up.

## Kept in the URL

The open tabs, their order and the current one are written in the hash of the
page (`#panels=<JSON>`, `history.replaceState` at every change): a reload, or
the link sent to someone, opens them again once the tree is drawn (the node of a
node tab is then selected). Detached tabs are not kept. The JSON is
`{"t": [[<modal id> | "node", <remote URL> | <hostnode uuid> | null, <title>], …], "a": <index of the current tab>}`.

The hash comes from a link anyone can write, so `restore()` only opens:
- modals of the page (an element `.modal` with that ID, not in `KEPT_AS_MODALS`);
- remote URLs of the same origin that are either the `data-remote` of an
  element of the page, or under the read-only detail pages (`/urls/`,
  `/hostnames/`, `/ips/`, `/favicon_details/`, `/capture_hash_details/`,
  `/body_hashes/`, `/identifier_details/`, `/cloudflare_ns/`), never the GET
  routes that change things (remove, rebuild…);
- node tabs with a valid UUID. At most 20 tabs; titles are shown as text.

The panel is not part of the tree: `js/capture_page.js` ignores presses inside
`#lk-side-panel` (no tree drag: texts can be selected, tabs dragged), Ctrl +
wheel over it does not zoom the tree (`js/tree.js`, `setupZoom`), and it has the
normal cursor, not the grab hand of the tree (same for the legend and the zoom
buttons). The wheel over the panel scrolls the panel only, never the page (the
tree): `overscroll-behavior: contain` on its body, and a `wheel` listener that
stops the wheel when nothing under the mouse can scroll that way any more (end
of the content, tab bar; the scrolling boxes inside the vitrine components
count, through `composedPath()`).

## Back and forward in a tab

A link inside the panel shown (a hostname, an IP, a hash... that opens the
details of the value) opens its page **in the same tab**, like a browser; the
←  / → buttons at the left of the tab bar (`#lk-side-panel-back`,
`#lk-side-panel-forward`) go through the pages seen in that tab. Ctrl / ⌘ +
click or a middle click opens it in a new tab instead, and the links of the
menus always open a tab.

In `js/side_panel.js`: each tab has `back` and `forward` lists of pages
(`{kind, modal, url, title}`); `navigate()` pushes the current page and loads
the new one, `goBack()` / `goForward()` move between them, `renderTabs()`
enables the buttons. Only the current page of each tab is kept in the URL
(`#panels=`): after a reload, the history of the tabs starts again.

While the panel is resized, its frames (the pages of the nodes) ignore the mouse
(`.is-resizing iframe { pointer-events: none }`): otherwise the frame keeps the
moves as soon as the mouse is over it, and the panel can only grow.
