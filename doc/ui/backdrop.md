# Decorative background

Every page extending `layouts/page.html` shows, behind its content, a faint
capture tree (`static/images/ui/backdrop-tree.svg`) and a glow in the accent
colour, centred in the window and fading out towards the edges. It is fixed
(it does not scroll) and stronger on the home page.

- Markup: `<div class="lk-backdrop" aria-hidden="true">` in `layouts/page.html`.
- CSS: `static/css/components/backdrop.css`. The SVG is used as a mask, so the
  tree takes the accent colour of the theme (light and dark).
- Strength: `--lk-backdrop-tree-opacity` and `--lk-backdrop-glow`, set on
  `body.lk-page`, raised on the home page (`body.lk-page-home`, set by
  `home/home.html` through the `body_class` block).
