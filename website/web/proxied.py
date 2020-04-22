#!/usr/bin/env python
# -*- coding: utf-8 -*-


class ReverseProxied():
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        scheme = environ.get('HTTP_X_FORWARDED_PROTO')
        if not scheme:
            scheme = environ.get('HTTP_X_SCHEME')

        if scheme:
            environ['wsgi.url_scheme'] = scheme
        return self.app(environ, start_response)
