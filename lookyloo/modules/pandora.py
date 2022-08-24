#!/usr/bin/env python3

import logging
from io import BytesIO
from typing import Any, Dict

from pypandora import PyPandora

from ..default import ConfigError, get_config
from ..helpers import get_useragent_for_requests


class Pandora():

    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        if not config.get('url'):
            self.available = False
            return

        self.client = PyPandora(root_url=config['url'], useragent=get_useragent_for_requests())

        if not self.client.is_up:
            self.available = False
            return

        self.available = True
        self.allow_auto_trigger = False

        if config.get('allow_auto_trigger'):
            self.allow_auto_trigger = True

    def capture_default_trigger(self, file_in_memory: BytesIO, filename: str, /, auto_trigger: bool=False) -> Dict:
        '''Automatically submit the file if the landing URL is a file instead of a webpage'''
        if not self.available:
            return {'error': 'Module not available'}
        if auto_trigger and not self.allow_auto_trigger:
            # NOTE: if auto_trigger is true, it means the request comes from the
            # auto trigger feature (disabled by default)
            return {'error': 'Auto trigger not allowed on module'}

        self.submit_file(file_in_memory, filename)
        return {'success': 'Module triggered'}

    def submit_file(self, file_in_memory: BytesIO, filename: str) -> Dict:
        '''Submit a file to Pandora'''
        if not self.available:
            raise ConfigError('Pandora not available, probably not able to reach the server.')

        return self.client.submit(file_in_memory, filename, seed_expire=0)
