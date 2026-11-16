# Capture page: header and menus

The capture page (`tree/tree.html`) has the site header and a capture bar on
top, instead of the old floating boxes (logo + "New capture" on the left,
menus on the right). Both stay at the top while the tree scrolls.

## Capture bar (`tree/capture_bar.html`)

Included in the `site_header` block of `tree/tree.html`.

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
