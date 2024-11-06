#!/usr/bin/env python
from typing import Any
from collections.abc import MutableMapping


class ReverseProxied():
    def __init__(self, app: Any) -> None:
        self.app = app

    def __call__(self, environ: MutableMapping[str, Any], start_response: Any) -> Any:
        scheme = environ.get('HTTP_X_FORWARDED_PROTO')
        if not scheme:
            scheme = environ.get('HTTP_X_SCHEME')

        if scheme:
            environ['wsgi.url_scheme'] = scheme
        return self.app(environ, start_response)
