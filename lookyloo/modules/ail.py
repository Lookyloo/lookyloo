#!/usr/bin/env python3

from __future__ import annotations

import logging

from typing import Any, TYPE_CHECKING

from pyail import PyAIL, PyAILError  # type: ignore[import-untyped]

from ..default import get_config
from ..helpers import global_proxy_for_requests

if TYPE_CHECKING:
    from lacuscore import CaptureResponseJson


class AIL():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.config = get_config('modules', 'AIL')
        self.available = self.config.get('enabled')

        if self.available and not self.config.get('url'):
            self.logger.info('No URL.')
            self.available = False
        if self.available and not self.config.get('apikey'):
            self.logger.info('No API key.')
            self.available = False

        try:
            self.client = PyAIL(self.config['url'], self.config['apikey'],
                                ssl=self.config.get('verify_tls_cert'),
                                timeout=self.config.get('timeout', 10),
                                proxies=global_proxy_for_requests(),
                                tool='lookyloo')
        except Exception as e:
            self.logger.error(f'Could not connect to AIL: {e}')
            self.available = False

    def submit(self, capture: CaptureResponseJson) -> dict[str, Any]:
        '''Submit a capture to AIL Framework
        '''
        try:
            return self.client.import_crawler_capture(capture)
        except PyAILError as e:
            return {'error': e}
