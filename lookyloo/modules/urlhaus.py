#!/usr/bin/env python3

from __future__ import annotations

import json
from datetime import date
from typing import Any, TYPE_CHECKING

import requests

from ..default import ConfigError, get_homedir
from ..helpers import get_cache_directory

if TYPE_CHECKING:
    from ..capturecache import CaptureCache

from .abstractmodule import AbstractModule


class URLhaus(AbstractModule):

    def module_init(self) -> bool:
        if not self.config.get('enabled'):
            self.logger.info('Not enabled')
            return False

        self.url = self.config.get('url')
        self.storage_dir_uh = get_homedir() / 'urlhaus'
        self.storage_dir_uh.mkdir(parents=True, exist_ok=True)
        return True

    def get_url_lookup(self, url: str) -> dict[str, Any] | None:
        url_storage_dir = get_cache_directory(self.storage_dir_uh, url, 'url')
        if not url_storage_dir.exists():
            return None
        cached_entries = sorted(url_storage_dir.glob('*'), reverse=True)
        if not cached_entries:
            return None

        with cached_entries[0].open() as f:
            return json.load(f)

    def __url_result(self, url: str) -> dict[str, Any]:
        data = {'url': url}
        response = requests.post(f'{self.url}/url/', data)
        response.raise_for_status()
        return response.json()

    def capture_default_trigger(self, cache: CaptureCache, /, *, force: bool=False,
                                auto_trigger: bool=False, as_admin: bool=False) -> dict[str, str]:
        '''Run the module on all the nodes up to the final redirect'''

        if error := super().capture_default_trigger(cache, force=force, auto_trigger=auto_trigger, as_admin=as_admin):
            return error

        # Check URLs up to the redirect
        if cache.redirects:
            for redirect in cache.redirects:
                self.__url_lookup(redirect)
        else:
            self.__url_lookup(cache.url)

        return {'success': 'Module triggered'}

    def __url_lookup(self, url: str) -> None:
        '''Lookup an URL on URL haus
        Note: It will trigger a request to URL haus every time *until* there is a hit (it's cheap), then once a day.
        '''
        if not self.available:
            raise ConfigError('URL haus not available, probably not enabled.')

        url_storage_dir = get_cache_directory(self.storage_dir_uh, url, 'url')
        url_storage_dir.mkdir(parents=True, exist_ok=True)
        uh_file = url_storage_dir / date.today().isoformat()

        if uh_file.exists():
            return

        url_information = self.__url_result(url)
        if (not url_information
            or ('query_status' in url_information
                and url_information['query_status'] in ['no_results', 'invalid_url'])):
            try:
                url_storage_dir.rmdir()
            except OSError:
                # Not empty.
                pass
            return

        with uh_file.open('w') as _f:
            json.dump(url_information, _f)
