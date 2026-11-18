# IP geolocation (flags and cards)

**For the moment, for the logged in users (admins) only**: the route answers
403 to the others, and the script and its stylesheet are only loaded for them.

Everywhere an IP is shown, a flag of its country is put before it, and the mouse
(or the focus) on the IP or its flag opens a small card (not on its copy button):
a **world map** with the country of the IP highlighted and a dot at its location, country (name, ISO codes), AS and
its organisation, location (average of the country), the databases used and
when they were built, and a **Download JSON** button (the answer of the service
as it is).

## Where

- IP pivot page (`investigate/ip.html`, `pivot_header(ip=True)`);
- Analysis > IP addresses and Hostnames (the IP column of the vitrine tables,
  `geoIp()` in `js/capture_panels.js`);
- node pages (`tree/hostname_popup.html`): the resolved IPs and the IP from the HAR.

Any element with `data-lk-ip="<ip>"` gets it (a `MutationObserver` also finds the
ones of the panels loaded later); in a shadow DOM, call
`lkIpGeo.decorate(node, ip)`.

## How

- The data comes from an [mmdb-server](https://github.com/adulau/mmdb-server)
  instance, `https://ip.circl.lu/geolookup/<ip>` by default
  (`ip_geolookup_url` in `config/generic.json`; an empty string disables the
  whole feature: no route answer, no script loaded).
- The browser never asks the service: it asks `/ip_geolookup?ip=...&ip=...`
  (at most 50 IPs at once, batched by the page), and the server of Lookyloo asks
  the service (`website/web/geolookup.py`), with a cache in memory (a day, 10 000
  IPs). Private, loopback and other non global IPs are not looked up.
- `static/js/components/ip_geo.js`: a small spinner is shown where the flag goes
  until the geolocation is there (inline style + Web Animations API, so it also
  turns inside the shadow DOM of the vitrine tables); the flag is an emoji (regional indicator
  symbols from the ISO code, no image), the card is one element of the page,
  placed under the IP (above it at the bottom of the screen); it stays open while
  the mouse is on it, Escape closes it. The values are written with `textContent`.
- `static/css/components/ip-geo.css`: tokens of `css/components/site.css` with
  Bootstrap variables as fallbacks (the node pages do not load the tokens).
- Both are loaded by `layouts/main.html` only when the feature is enabled
  (`ip_geo_enabled()` Jinja global) and the user is logged in.

## World map

The map of the card is drawn with D3 (already used by the tree) from
[world-atlas](https://github.com/topojson/world-atlas) (`countries-110m.json`,
about 100 KB) and [topojson-client](https://github.com/topojson/topojson-client),
installed in `static/vendor/` by `tools/3rdparty.py` (`world_atlas_version`,
`topojson_client_version`), never in the repository. They are only loaded the
first time a card is opened (`loadWorld()` in `js/components/ip_geo.js`): their
URLs and SRI come from `data-*` attributes of the `ip_geo.js` script tag
(`layouts/main.html`), the scripts are added with their `integrity`, the map is
fetched with its SRI. The country is found by its ISO numeric code (the ids of
world-atlas, `Numeric code` of the answer), the dot is at the average location of
the country (Natural Earth projection, 292 x 150).
