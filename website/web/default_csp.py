#!/usr/bin/env python3
from typing import Any

SELF: str = "'self'"

csp: dict[str, Any] = {
    'default-src': SELF,
    'base-uri': SELF,
    'img-src': [
        SELF,
        "data:",
        "blob:",
        "'unsafe-inline'"
    ],
    'script-src': [
        SELF,
        "'strict-dynamic'",
        "'unsafe-inline'",
        "http:",
        "https:"
    ],
    'script-src-elem': [
        SELF,
        # Cannot enable that because https://github.com/python-restx/flask-restx/issues/252
        # "'strict-dynamic'",
        "'unsafe-inline'",
    ],
    'style-src': [
        SELF,
        "'unsafe-inline'"
    ],
    'media-src': [
        SELF,
        "data:",
        "blob:",
        "'unsafe-inline'"
    ],
    'frame-ancestors': [
        SELF,
    ],
}
