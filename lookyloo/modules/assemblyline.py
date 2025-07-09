#!/usr/bin/env python3

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from assemblyline_client import get_client  # type: ignore[import-untyped]

from ..default import ConfigError, get_config
from .abstractmodule import AbstractModule

if TYPE_CHECKING:
    from ..capturecache import CaptureCache

# TODO: Add support for proxies, once this PR is merged: https://github.com/CybercentreCanada/assemblyline_client/pull/64


class AssemblyLine(AbstractModule):

    def module_init(self) -> bool:
        if not self.config.get('apikey'):
            self.logger.info('No API key.')
            return False

        self.al_client = get_client(self.config.get('url'),
                                    apikey=(self.config.get('username'),
                                            self.config.get('apikey')))
        self.logger.info(f'AssemblyLine module initialized successfully ({self.config.get("url")}).')
        return True

    def capture_default_trigger(self, cache: CaptureCache, /, *, force: bool,
                                auto_trigger: bool, as_admin: bool) -> dict[str, Any]:
        '''Run the module on the initial URL'''

        if error := super().capture_default_trigger(cache, force=force, auto_trigger=auto_trigger, as_admin=as_admin):
            return error

        response = self._submit(cache)
        self.logger.debug(f'Submitted {cache.url} to AssemblyLine: {response}')
        return {'success': response}

    def _submit(self, cache: CaptureCache) -> dict[str, Any]:
        '''Submit a URL to AssemblyLine
        '''
        if not self.available:
            raise ConfigError('AssemblyLine not available, probably no API key')
        if cache.url.startswith('file'):
            return {'error': 'AssemblyLine integration does not support files.'}

        params = {'classification': self.config.get('classification'),
                  'services': self.config.get('services'),
                  'priority': self.config.get('priority')}
        lookyloo_domain = get_config('generic', 'public_domain')
        metadata = {'lookyloo_uuid': cache.uuid,
                    'lookyloo_url': f'https://{lookyloo_domain}/tree/{cache.uuid}',
                    'source': 'lookyloo'}

        if self.autosubmit:
            # submit is allowed and we either force it, or it's just allowed
            try:
                response = self.al_client.ingest(url=cache.url, fname=cache.url,
                                                 params=params,
                                                 nq=self.config.get('notification_queue'),
                                                 submission_profile=self.config.get('submission_profile'),
                                                 metadata=metadata)
                if 'error' in response:
                    self.logger.error(f'Error submitting to AssemblyLine: {response["error"]}')
                return response
            except Exception as e:
                return {'error': e}
        return {'error': 'Submitting is not allowed by the configuration'}

    def get_notification_queue(self) -> list[dict[str, Any]]:
        '''Get the NQ from AssemblyLine'''
        if not self.config.get('notification_queue'):
            self.logger.warning('No notification queue configured for AssemblyLine.')
            return []
        try:
            return self.al_client.ingest.get_message_list(nq=self.config.get('notification_queue'))
        except Exception as e:
            self.logger.error(f'Error getting notification queue: {e}')
            return []
