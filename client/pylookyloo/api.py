#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json

from urllib.parse import urljoin


class Lookyloo():

    def __init__(self, root_url: str='https://lookyloo.circl.lu/'):
        self.root_url = root_url
        if not self.root_url.endswith('/'):
            self.root_url += '/'
        self.session = requests.session()

    @property
    def is_up(self) -> bool:
        r = self.session.head(self.root_url)
        return r.status_code == 200

    def enqueue(self, url: str) -> str:
        response = self.session.post(urljoin(self.root_url, 'submit'), data=json.dumps({'url': url}))
        return urljoin(self.root_url, f'tree/{response.text}')
