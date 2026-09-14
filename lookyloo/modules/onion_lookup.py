#!/usr/bin/env python3

from __future__ import annotations

import logging

from typing import Any, TYPE_CHECKING
from urllib.parse import urlparse, urljoin
from urllib3.util import Retry

import requests
from requests.adapters import HTTPAdapter

from ..default import get_config
from ..helpers import global_proxy_for_requests, get_useragent_for_requests

if TYPE_CHECKING:
    from ..capturecache import CaptureCache


class OnionLookup():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.config = get_config('modules', 'OnionLookup')
        self.available = self.config.get('enabled')

        if self.available:
            self.session = requests.session()
            retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
            self.session.mount('http://', HTTPAdapter(max_retries=retries))
            self.session.headers['user-agent'] = get_useragent_for_requests()
            if proxies := global_proxy_for_requests():
                self.session.proxies.update(proxies)

            self.root_url = 'https://onion.ail-project.org'

    def lookup(self, cache: CaptureCache) -> dict[str, Any]:
        '''Submit a URL to AIL Framework
        '''
        lookups: dict[str, Any] = {}
        # We only submit .onions URLs up to the landing page
        for redirect in cache.redirects:
            parsed = urlparse(redirect)
            if parsed.hostname and parsed.hostname.endswith('.onion'):
                try:
                    response = requests.get(urljoin(self.root_url, f'/api/lookup/{parsed.hostname}'), timeout=10)
                    response.raise_for_status()
                    if content := response.json():
                        self.logger.info(f'[{parsed.hostname}]: Is known.')
                        lookups[parsed.hostname] = content
                    else:
                        self.logger.info(f'[{parsed.hostname}]: Is unknown.')
                        lookups[parsed.hostname] = None
                except Exception as e:
                    self.logger.error(f'Error checking URL against onion lookup: {e}')
                    lookups[parsed.hostname] = f"Unable to check {redirect}: {e}"
        return lookups
