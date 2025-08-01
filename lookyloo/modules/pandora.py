#!/usr/bin/env python3

from __future__ import annotations

import logging

from io import BytesIO
from typing import Any

from pypandora import PyPandora

from ..default import get_config, LookylooException
from ..helpers import get_useragent_for_requests, global_proxy_for_requests


class Pandora():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.config = get_config('modules', 'Pandora')
        self._enabled = True
        if not self.config.get('url'):
            self.logger.info('No URL in config.')
            self._enabled = False
        self.client = PyPandora(root_url=self.config['url'], useragent=get_useragent_for_requests(),
                                proxies=global_proxy_for_requests())

    @property
    def available(self) -> bool:
        if not self._enabled:
            return False
        return self.client.is_up

    def submit_file(self, file_in_memory: BytesIO, filename: str) -> dict[str, Any]:
        '''Submit a file to Pandora'''
        if not self.available:
            raise LookylooException('Pandora not available, probably not able to reach the server.')

        return self.client.submit(file_in_memory, filename, seed_expire=0)
