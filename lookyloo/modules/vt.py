#!/usr/bin/env python3

import json
import logging
import time
from datetime import date
from typing import Any, Dict, Optional, TYPE_CHECKING

import vt  # type: ignore
from vt.error import APIError  # type: ignore

from ..default import ConfigError, get_homedir, get_config
from ..helpers import get_cache_directory

if TYPE_CHECKING:
    from ..capturecache import CaptureCache


class VirusTotal():

    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        if not config.get('apikey'):
            self.available = False
            return

        self.available = True
        self.autosubmit = False
        self.allow_auto_trigger = False
        self.client = vt.Client(config['apikey'])

        if config.get('allow_auto_trigger'):
            self.allow_auto_trigger = True

        if config.get('autosubmit'):
            self.autosubmit = True

        self.storage_dir_vt = get_homedir() / 'vt_url'
        self.storage_dir_vt.mkdir(parents=True, exist_ok=True)

    def get_url_lookup(self, url: str) -> Optional[Dict[str, Any]]:
        url_storage_dir = get_cache_directory(self.storage_dir_vt, vt.url_id(url))
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
        '''Lookup an URL on VT
        Note: force means 2 things:
            * (re)scan of the URL
            * re fetch the object from VT even if we already did it today

        Note: the URL will only be sent for scan if autosubmit is set to true in the config
        '''
        if not self.available:
            raise ConfigError('VirusTotal not available, probably no API key')

        url_storage_dir = get_cache_directory(self.storage_dir_vt, vt.url_id(url))
        url_storage_dir.mkdir(parents=True, exist_ok=True)
        vt_file = url_storage_dir / date.today().isoformat()

        scan_requested = False
        if self.autosubmit and force:
            try:
                self.client.scan_url(url)
            except APIError as e:
                if e.code == 'QuotaExceededError':
                    self.logger.warning('VirusTotal quota exceeded, sry.')
                    return
                self.logger.exception('Something went poorly withi this query.')
            scan_requested = True

        if not force and vt_file.exists():
            return

        url_id = vt.url_id(url)
        for _ in range(3):
            try:
                url_information = self.client.get_object(f"/urls/{url_id}")
                with vt_file.open('w') as _f:
                    json.dump(url_information.to_dict(), _f)
                break
            except APIError as e:
                if not self.autosubmit:
                    break
                if not scan_requested and e.code == 'NotFoundError':
                    try:
                        self.client.scan_url(url)
                        scan_requested = True
                    except APIError as e:
                        self.logger.warning(f'Unable to trigger VirusTotal on {url}: {e}')
                        break
            time.sleep(5)
