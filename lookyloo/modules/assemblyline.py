#!/usr/bin/env python3

from __future__ import annotations

from typing import Any, TYPE_CHECKING

import requests

from ..default import ConfigError, get_config

from .abstractmodule import AbstractModule

from assemblyline_client import get_client

if TYPE_CHECKING:
    from ..capturecache import CaptureCache


class AssemblyLine(AbstractModule):

    def module_init(self) -> bool:
        if not self.config.get('apikey'):
            self.logger.info('No API key.')
            return False
        
        self.al_client = get_client(self.config.get('url'), apikey=(self.config.get('username'), self.config.get('apikey')))
        self.domain = get_config('generic', 'public_domain')
        self.logger.debug(self.domain)
        
        self.logger.info('AssemblyLine module initialized successfully.')

        return True

    def capture_default_trigger(self, cache: CaptureCache, /, *, force: bool,
                                auto_trigger: bool, as_admin: bool) -> dict[str, str]:
        '''Run the module on the initial URL'''

        if error := super().capture_default_trigger(cache, force=force, auto_trigger=auto_trigger, as_admin=as_admin):
            return error

        response = self.__url_submit(cache.url, cache.uuid)
        return {'success': response}

    def __submit_url(self, url: str, uuid: str) -> bool:
        self.logger.debug(f'Submitting URL to AssemblyLine: {url}')
        self.logger.debug(f'UUID: {uuid}')
        self.logger.debug(f'Tree URL: https://{self.domain}/tree/{uuid}')
        
        settings = {
            'url': url,
            'name': url,
            'nq': self.config.get('nq', 'lookyloo'), # notification queue name
            'submission_profile': self.config.get('submission_profile', 'static_with_internet'),
            'params': {
                'classification': self.config.get('classification', 'TLP:AMBER+STRICT'),
            },
            'metadata': {
                'lookyloo_uuid': uuid,
                'lookyloo_url': f'https://{self.domain}/tree/{uuid}',
            },
        }
        self.logger.debug(f'Submission settings: {settings}')
        
        response = self.al_client.ingest(url=settings['url'], 
                                         fname=settings['name'], 
                                         params=settings['params'], 
                                         nq=settings['nq'], 
                                         submission_profile=settings['submission_profile'],
                                         metadata=settings['metadata'])
        
        self.logger.debug(f'Response from AssemblyLine: \n{response}')
        return response

    def __url_submit(self, url: str, uuid: str) -> dict[str, Any]:
        '''Submit a URL to AssemblyLine
        '''
        if not self.available:
            raise ConfigError('AssemblyLine not available, probably no API key')
        if url.startswith('file'):
            return {'error': 'AssemblyLine integration does not support files.'}

        if self.autosubmit:
            # submit is allowed and we either force it, or it's just allowed
            try:
                return self.__submit_url(url, uuid)
            except requests.exceptions.HTTPError as e:
                return {'error': e}
        return {'error': 'Submitting is not allowed by the configuration'}
