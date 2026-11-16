# Capture page: header and menus

The capture page (`tree/tree.html`) has the site header and a capture bar on
top, instead of the old floating boxes (logo + "New capture" on the left,
menus on the right). Both stay at the top while the tree scrolls.

## Capture bar (`tree/capture_bar.html`)

Included in the `site_header` block of `tree/tree.html`. The top block (site
header + capture bar) is `position: fixed`, not sticky: a zoomed tree is wider
than the window and the page scrolls sideways, a sticky bar would scroll away
to the left. `js/capture_page.js` keeps `--lk-capture-top-height` equal to its
height; the page starts under it.

- **What was captured**: the screenshot thumbnail (click: screenshot modal),
  the favicon and the title of the page, the URL with a copy button, the time,
  the number of redirects, the visibility (Public / Unlisted / Private, click:
  visibility modal) and the categories.
- **Menus**, with an icon per entry:
  - **Capture**: details, statistics, storage state, console messages,
    downloads, video, screenshot, MISP export.
  - **Analysis**: index capture (when needed), third parties (reports, MISP
    lookup, historical lookups, Hashlookup), in this capture (resources, IPs,
    hostnames, URLs, favicons, hashes types, identifiers, Cloudflare name servers).
  - **Actions**: re-capture, subsequent captures, monitoring; Organize
    (categories, unbookmark, mark as known: the former Extras menu); Share &
    export (visibility, MISP push, push to another Lookyloo).
  - **Download**: full capture (zip), screenshot, HAR, forensic acquisition.
  - **Admin** (logged in): rebuild, Ollama report, remove capture.
  - **Report suspicious capture** (when mail notification is on) and the
    manual (`?`).
- **Fold button** (top right): the bar shrinks to one line, the menus show
  their icons only. Remembered in `localStorage` (`js/capture_page.js`).
- Phones: the menus show their icons only.

No new modal and no new route: every entry opens the same modal (same IDs and
`data-remote`) or link as before. `js/tree.js` still reads `#menu_vertical`
(the bar), `#menu_horizontal` and `#menu_horizontal_content` (the menus).

## Styles

`css/components/capture-bar.css`, with the `--lk-*` tokens of `site.css`
(light and dark). `css/tree.css` lost the rules of the old floating menus
(including a global `.dropdown-menu` width of 180px).

## Legend & filter (`tree/legend.html`)

A panel at the bottom right (a `<details>`, open by default) replaces the old
static legend. Each entry is a button carrying the data key of the node icon
it explains (`data-key`: the keys of `icon_list()` in `js/tree.js`).

- When the tree is loaded, `setupLegendFilter()` counts the nodes having each
  icon. The icons of this capture stay at the top, most frequent first, with
  their count; the others go to the folded "Not in this capture" list.
- A click on an entry selects it (several can be selected: a node matches if
  it has **any** of them). The matching nodes are outlined, the others dimmed;
  the summary shows the number of matching nodes. "Clear the filter" resets it.
- The filter is applied again after a node is expanded or collapsed.
- Nodes are only dimmed, never removed: the tree keeps its shape.

## Zoom and drag

- **Zoom** (`js/tree.js`, `setupZoom`): the `−` / `100 %` / `+` buttons at
  the top right, just under the capture bar (`#tree-zoom`), or Ctrl + wheel
  over the tree. Limited to 25 %–200 % (below, the cards are unreadable; above,
  one card no longer fits the window); `−` / `+` are disabled at the limits.
  The point under the mouse (or the centre of the window for the buttons) stays
  in place; `100 %` resets. The SVG keeps the coordinates of the layout in its
  `viewBox` and is drawn at its size times the zoom, so nodes, links, tooltips
  and the legend filter are not affected.
- **Free room**: half the window of empty space on each side of the tree
  (`#tree_svg` padding `50vh 50vw`, `css/tree.css`), so the tree can be moved
  far past its edges.
- **Center** (`#tree-center`, `centerOnRoot`): brings the first node of the
  tree (the root, the node without parent) to the middle of the window, under
  the capture bar. The page opens that way too (unless the link points to a
  node: then that node is shown).
- **Background** (`#tree-background`, `setBackground`): a button next to
  Center opens the list:
  dots (default), columns (one stripe per depth, the former background) or
  plain. Remembered in `localStorage` (`lk-tree-background`). The dots are a
  CSS background of the `body` (`lk-bg-dots`), which fills the whole page
  however far it is dragged; the columns
  are the `#backstripes` pattern of the SVG.
- **Drag** (`js/capture_page.js`): press anywhere on the tree and move to move
  around it (the page scrolls). A press without movement is still a normal
  click; after a drag the click is swallowed. Links, buttons and the legend are
  not draggable. The scroll is `instant`: Bootstrap makes the page scroll
  smooth, which would lag behind the mouse.
