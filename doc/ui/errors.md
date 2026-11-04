# Error pages

Template `errors/error.html`, styles `static/css/errors.css`. The eyes of the
loader as an illustration, the error code, a title, a message and links back to
the home page, the recent captures and the search.

Handlers in `website/web/__init__.py`:

- **404** (`handle_not_found`): "Page not found", with the requested path.
- **500** (`handle_server_error`): "Something went wrong" (the traceback is
  still logged by Flask).
- The errors raised by the capture views (`IndexError`, ...) keep their own
  handlers and render the same template with their message.

Clients that do not accept HTML (API, scripts) get JSON instead:
`{"message": "Not found."}` / `{"message": "Internal server error."}`, with
the same status code.

Variables of the template: `error_message`, and optionally `error_title`,
`error_code`, `requested_path`.
