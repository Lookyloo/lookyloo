#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from urllib.parse import urljoin

import requests


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

    def enqueue(self, url: Optional[str]=None, **kwargs) -> str:
        if not url and 'url' not in kwargs:
            raise Exception(f'url entry required: {kwargs}')

        if url:
            to_send = {'url': url, **kwargs}
        else:
            to_send = kwargs
        response = self.session.post(urljoin(self.root_url, 'submit'), json=to_send)
        return urljoin(self.root_url, f'tree/{response.text}')
