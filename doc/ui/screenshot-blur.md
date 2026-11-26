# Screenshot blurred at first (capture page)

A capture can show shocking content (gore, porn, scam pages...). On the
capture page (`tree/tree.html`), the screenshot is therefore **always blurred
at first**, whatever `enable_default_blur_screenshot` says (this setting is no
longer read by the capture page; it is kept in `config/generic.json` for
compatibility):

- the screenshot of the **Screenshot** panel (`#screenshot`, class `blur`,
  `blur(20px)`);
- the 64 px thumbnail on the landing node of the tree (`#screenshot_thumbnail`,
  drawn by `js/tree.js`, `blur(3px)`).

The analyst then reveals it as they want, with the controls above the image
(`#screenshotBlur`, `setupScreenshotBlur()` in `js/tree_modals.js`):

- **Unblur** / **Blur** in the header (`#blurScreenshot`, `aria-pressed`): 0 %
  or back to 100 % in one click;

- **Blur** slider (`#blurLevel`), from 0 to 100 % (100 % = 20 px), with the
  value next to it (`#blurLevelValue`), and presets 100 / 50 / 25 / 0 %;
- **Reveal slowly** (`#revealScreenshot`): the blur goes down little by little
  from the current level to 0 (8 s from 100 %); click again to pause, the
  slider or a preset stops it too;
- **Spotlight** (`#spotlightScreenshot`, `aria-pressed`): a clear circle
  follows the mouse over the blurred screenshot (a clear copy of the image,
  `#screenshotSpot`, masked with a radial gradient at `--lk-spot-x/y`).

The thumbnail of the tree follows the level (0 to 3 px). Nothing is
remembered: every new page load starts at 100 %. **Download** gives the
original file.

Same idea as the previews of the list of the captures (doc/ui/capture-list.md).
