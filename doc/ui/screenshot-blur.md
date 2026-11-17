# Screenshot blurred at first (capture page)

A capture can show shocking content (gore, porn, scam pages...). On the
capture page (`tree/tree.html`), the screenshot is therefore **always blurred
at first**, whatever `enable_default_blur_screenshot` says (this setting is no
longer read by the capture page; it is kept in `config/generic.json` for
compatibility):

- the screenshot of the **Screenshot** modal (`#screenshot`, class `blur`,
  `filter: blur(10px)` in `css/tree.css`), with an **Unblur** / **Blur**
  button (`#blurScreenshot`, `aria-pressed`);
- the 64 px thumbnail on the landing node of the tree (`#screenshot_thumbnail`,
  drawn by `js/tree.js`, `blur(3px)`).

`js/tree_modals.js` toggles both together: unblur the screenshot, the
thumbnail is unblurred too, and the other way round. Nothing is remembered:
every new page load starts blurred. **Download** gives the original file.

Same idea as the previews of the list of the captures (doc/ui/capture-list.md).
