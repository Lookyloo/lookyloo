# Toasts (flashed messages)

The messages Flask flashes (`flash()` in `website/web/__init__.py`: "The capture
has not been indexed yet", "Video(s) have been triggered", errors...) are shown
the same way on every page, as toasts: a stack at the bottom right of the
screen, left of the side panel on the capture page
(`--lk-side-panel-space`, see [side-panel.md](side-panel.md)), the whole width on
phones.

- `templates/partials/toasts.html`, macro `toasts()`, called once by
  `layouts/main.html` (every page). It replaces the `render_messages()` of
  bootstrap-flask that a few pages called, each in its own place (the full-width
  alerts at the bottom of the tree).
- One toast per message: an icon and a colour by category (`error` /
  `critical` / `danger`: red, `warning`: amber, `success`: green, anything
  else: info, blue), the message, a close button.
- Errors and warnings stay until closed. Info and success go away after 7
  seconds: a thin bar at the bottom shows the time left, paused while the mouse
  (or the focus) is on the toast. The time only runs while the page is on screen
  (`document.visibilityState`, `.lk-toasts.is-seen`): a page opened in a
  background tab keeps its toasts until it is shown, and they pause again when
  another tab is shown.
- `static/css/components/toasts.css`: tokens of `css/components/site.css`, with
  Bootstrap variables as fallbacks (the node pages do not load the tokens);
  light and dark. Slides in, slides out; no animation with reduced motion.
- `static/js/components/toasts.js`: the close buttons and the end of the
  timer; the stack is removed with its last toast.
- Errors and warnings are `role="alert"`, the others `role="status"`.

The messages flashed by a panel loaded in the side panel (an HTML fragment) are
shown with the next full page, like before.
