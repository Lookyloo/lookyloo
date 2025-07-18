#!/usr/bin/env python3

from __future__ import annotations

from typing import Any, TYPE_CHECKING

import requests

from ..default import ConfigError
from ..helpers import prepare_global_session

from .abstractmodule import AbstractModule

if TYPE_CHECKING:
    from ..capturecache import CaptureCache


class FOX(AbstractModule):

    def module_init(self) -> bool:
        if not self.config.get('apikey'):
            self.logger.info('No API key.')
            return False

        self.client = prepare_global_session()
        self.client.headers['X-API-KEY'] = self.config['apikey']
        self.client.headers['Content-Type'] = 'application/json'

        return True

    def capture_default_trigger(self, cache: CaptureCache, /, *, force: bool,
                                auto_trigger: bool, as_admin: bool) -> dict[str, str]:
        '''Run the module on the initial URL'''

        if error := super().capture_default_trigger(cache, force=force, auto_trigger=auto_trigger, as_admin=as_admin):
            return error

        self.__url_submit(cache.url)
        return {'success': 'Module triggered'}

    def __submit_url(self, url: str) -> bool:
        if not url.startswith('http'):
            url = f'http://{url}'
        data = {'url': url}

        response = self.client.post('https://ingestion.collaboration.cyber.gc.ca/v1/url', json=data, timeout=1)
        response.raise_for_status()
        return True

    def __url_submit(self, url: str) -> dict[str, Any]:
        '''Submit a URL to FOX
        '''
        if not self.available:
            raise ConfigError('FOX not available, probably no API key')
        if url.startswith('file'):
            return {'error': 'FOX does not support files.'}

        if self.autosubmit:
            # submit is allowed and we either force it, or it's just allowed
            try:
                self.__submit_url(url)
            except requests.exceptions.HTTPError as e:
                return {'error': e}
            self.logger.info('URL submitted to FOX ({url})')
            return {'success': 'URL submitted successfully'}
        return {'error': 'Submitting is not allowed by the configuration'}
