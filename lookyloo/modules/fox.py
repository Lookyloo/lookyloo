#!/usr/bin/env python3

from typing import Dict

import requests

from ..default import ConfigError
from ..helpers import get_useragent_for_requests

from .abstractmodule import AbstractModule


class FOX(AbstractModule):

    def module_init(self) -> bool:
        if not self.config.get('apikey'):
            self.logger.info('No API key.')
            return False

        self.autosubmit = False
        self.allow_auto_trigger = False
        self.client = requests.session()
        self.client.headers['User-Agent'] = get_useragent_for_requests()
        self.client.headers['X-API-KEY'] = self.config['apikey']
        self.client.headers['Content-Type'] = 'application/json'

        self.allow_auto_trigger = bool(self.config.get('allow_auto_trigger', False))
        self.autosubmit = bool(self.config.get('autosubmit', False))

        return True

    def capture_default_trigger(self, url: str, /, auto_trigger: bool=False) -> Dict:
        '''Run the module on the initial URL'''
        if not self.available:
            return {'error': 'Module not available'}
        if auto_trigger and not self.allow_auto_trigger:
            # NOTE: if auto_trigger is true, it means the request comes from the
            # auto trigger feature (disabled by default)
            # Each module can disable auto-trigger to avoid depleating the
            # API limits.
            return {'error': 'Auto trigger not allowed on module'}

        self.url_submit(url)
        return {'success': 'Module triggered'}

    def __submit_url(self, url: str, ) -> bool:
        if not url.startswith('http'):
            url = f'http://{url}'
        data = {'url': url}

        response = self.client.post('https://ingestion.collaboration.cyber.gc.ca/v1/url', json=data, timeout=1)
        response.raise_for_status()
        return True

    def url_submit(self, url: str) -> Dict:
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
