# Back to top

Round button at the bottom right of every page extending `layouts/page.html`
(`#lk-back-to-top`, added after the footer). It appears after 400 px of
scrolling, scrolls back to the top (instantly with `prefers-reduced-motion`)
and is out of the keyboard order while hidden. The footer keeps room on its
right so the button never covers its links.

- `static/js/components/back_to_top.js`
- `static/css/components/back-to-top.css`
