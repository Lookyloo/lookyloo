#!/usr/bin/env python3

import json
import time

from datetime import date
from typing import Any, Dict, Optional, TYPE_CHECKING

from pyeupi import PyEUPI

from ..default import ConfigError, get_homedir
from ..helpers import get_cache_directory

if TYPE_CHECKING:
    from ..capturecache import CaptureCache

from .abstractmodule import AbstractModule


class PhishingInitiative(AbstractModule):

    def module_init(self) -> bool:
        if not self.config.get('apikey'):
            self.logger.info('No API key')
            return False

        self.allow_auto_trigger = False
        self.client = PyEUPI(self.config['apikey'])

        self.autosubmit = self.config.get('autosubmit', False)
        self.allow_auto_trigger = self.config.get('allow_auto_trigger', False)

        self.storage_dir_eupi = get_homedir() / 'eupi'
        self.storage_dir_eupi.mkdir(parents=True, exist_ok=True)
        return True

    def get_url_lookup(self, url: str) -> Optional[Dict[str, Any]]:
        url_storage_dir = get_cache_directory(self.storage_dir_eupi, url)
        if not url_storage_dir.exists():
            return None
        cached_entries = sorted(url_storage_dir.glob('*'), reverse=True)
        if not cached_entries:
            return None

        with cached_entries[0].open() as f:
            return json.load(f)

    def capture_default_trigger(self, cache: 'CaptureCache', /, *, force: bool=False, auto_trigger: bool=False) -> Dict:
        '''Run the module on all the nodes up to the final redirect'''
        if not self.available:
            return {'error': 'Module not available'}
        if auto_trigger and not self.allow_auto_trigger:
            return {'error': 'Auto trigger not allowed on module'}

        if cache.redirects:
            for redirect in cache.redirects:
                self.url_lookup(redirect, force)
        else:
            self.url_lookup(cache.url, force)
        return {'success': 'Module triggered'}

    def url_lookup(self, url: str, force: bool=False) -> None:
        '''Lookup an URL on Phishing Initiative
        Note: force means 2 things:
            * (re)scan of the URL
            * re fetch the object from Phishing Initiative even if we already did it today

        Note: the URL will only be sent for scan if autosubmit is set to true in the config
        '''
        if not self.available:
            raise ConfigError('PhishingInitiative not available, probably no API key')

        url_storage_dir = get_cache_directory(self.storage_dir_eupi, url)
        url_storage_dir.mkdir(parents=True, exist_ok=True)
        pi_file = url_storage_dir / date.today().isoformat()

        scan_requested = False
        if self.autosubmit and force:
            self.client.post_submission(url, comment='Received on Lookyloo')
            scan_requested = True

        if not force and pi_file.exists():
            return

        for _ in range(3):
            url_information = self.client.lookup(url)
            if not url_information['results']:
                # No results, that should not happen (?)
                break
            if url_information['results'][0]['tag'] == -1:
                # Not submitted
                if not self.autosubmit:
                    break
                if not scan_requested:
                    self.client.post_submission(url, comment='Received on Lookyloo')
                    scan_requested = True
                time.sleep(1)
            else:
                with pi_file.open('w') as _f:
                    json.dump(url_information, _f)
                break
