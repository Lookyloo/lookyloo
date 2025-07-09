#!/usr/bin/env python3

from __future__ import annotations

from typing import Any, TYPE_CHECKING
from urllib.parse import urlparse

from pyail import PyAIL  # type: ignore[import-untyped]

from ..default import ConfigError
from ..helpers import global_proxy_for_requests

from .abstractmodule import AbstractModule

if TYPE_CHECKING:
    from ..capturecache import CaptureCache


class AIL(AbstractModule):

    def module_init(self) -> bool:
        if not self.config.get('url'):
            self.logger.info('No URL.')
            return False
        if not self.config.get('apikey'):
            self.logger.info('No API key.')
            return False

        try:
            self.client = PyAIL(self.config['url'], self.config['apikey'],
                                ssl=self.config.get('verify_tls_cert'),
                                timeout=self.config.get('timeout', 10),
                                proxies=global_proxy_for_requests(),
                                tool='lookyloo')
        except Exception as e:
            self.logger.error(f'Could not connect to AIL: {e}')
            return False
        # self.client.headers['User-Agent'] = get_useragent_for_requests()  # Not supported
        return True

    def capture_default_trigger(self, cache: CaptureCache, /, *, force: bool,
                                auto_trigger: bool, as_admin: bool) -> dict[str, Any]:
        '''Run the module on the initial URL'''

        if error := super().capture_default_trigger(cache, force=force, auto_trigger=auto_trigger, as_admin=as_admin):
            return error

        return self._submit(cache)

    def _submit(self, cache: CaptureCache) -> dict[str, Any]:
        '''Submit a URL to AIL Framework
        '''
        if not self.available:
            raise ConfigError('AIL not available.')

        success: dict[str, str] = {}
        error: list[str] = []
        # We only submit .onions URLs up to the landing page
        for redirect in cache.redirects:
            parsed = urlparse(redirect)
            if parsed.hostname and parsed.hostname.endswith('.onion'):
                try:
                    response = self.client.onion_lookup(parsed.hostname)
                    if 'error' in response:
                        self.logger.info(f'[{parsed.hostname}]: {response.get("error")}')
                    else:
                        self.logger.info(f'[{parsed.hostname}]: Is already known.')
                    if r := self.client.crawl_url(redirect):
                        if 'error' in r:
                            self.logger.error(f'Error submitting {redirect} to AIL: {r.get("error")}')
                            error.append(f"Unable to submit {redirect}: {r.get('error')}")
                        else:
                            success[r.get('uuid')] = redirect
                except Exception as e:
                    self.logger.error(f'Error submitting URL to AIL: {e}')
                    error.append(f"Unable to submit {redirect}: {e}")
        return {'success': success, 'error': error}
