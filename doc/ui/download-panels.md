# Download panels (capture page)

The panels of the **Download** menu of the capture page, opened in the side panel,
styled like the other ones ([capture-panels.md](capture-panels.md)).

## Forensic acquisition

`tree/modals/download_elements.html` (`download_elements()` in
`website/web/__init__.py`):

- the header links to the zip with every element and its timestamp
  (`all_trusted_timestamp`);
- **Elements with a trusted timestamp** (RFC 3161): a vitrine `<vt-table>`
  (`TABLES.forensic` in `js/capture_panels.js`, rows built by the route: element,
  download, time and the `.tsr` of its timestamp, validation as a short badge, "Valid" in green or
  "Not validated" in amber with the message of the service as title, a dash
  without timestamp; the time as `YYYY-MM-DD HH:MM:SS`, local time, in full as title). The
  downloaded file and the video come with their name and their content when the
  capture has them. Then the link to the certificates used (`certificates.pem`);
- **Other exports**: one card per export with its Download button (Markdown, the
  tree as PNG `#dlTreeAsSVG`, cookie jar, hashes, full capture, MISP event, with
  the parents, redirects);
- **Check a timestamp yourself**: the OpenSSL commands and their output in vitrine
  `<vt-terminal>` (copy button per command);
- the error of the timestamps service, when there is one, is said at the top.
