#!/usr/bin/env python3

from __future__ import annotations

import json

from datetime import date
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from pypdns import PyPDNS, PDNSRecord

from ..default import ConfigError, get_homedir
from ..helpers import get_cache_directory

if TYPE_CHECKING:
    from ..capturecache import CaptureCache

from .abstractmodule import AbstractModule


class CIRCLPDNS(AbstractModule):

    def module_init(self) -> bool:
        if not (self.config.get('user') and self.config.get('password')):
            self.logger.info('Missing credentials.')
            return False

        self.pypdns = PyPDNS(basic_auth=(self.config['user'], self.config['password']))

        self.allow_auto_trigger = bool(self.config.get('allow_auto_trigger', False))

        self.storage_dir_pypdns = get_homedir() / 'circl_pypdns'
        self.storage_dir_pypdns.mkdir(parents=True, exist_ok=True)
        return True

    def get_passivedns(self, query: str) -> list[PDNSRecord] | None:
        # The query can be IP or Hostname. For now, we only do it on domains.
        url_storage_dir = get_cache_directory(self.storage_dir_pypdns, query, 'pdns')
        if not url_storage_dir.exists():
            return None
        cached_entries = sorted(url_storage_dir.glob('*'), reverse=True)
        if not cached_entries:
            return None

        with cached_entries[0].open() as f:
            return [PDNSRecord(record) for record in json.load(f)]

    def capture_default_trigger(self, cache: CaptureCache, /, *, force: bool=False, auto_trigger: bool=False) -> dict[str, str]:
        '''Run the module on all the nodes up to the final redirect'''
        if not self.available:
            return {'error': 'Module not available'}
        if auto_trigger and not self.allow_auto_trigger:
            return {'error': 'Auto trigger not allowed on module'}
        if cache.url.startswith('file'):
            return {'error': 'CIRCL Passive DNS does not support files.'}

        if cache.redirects:
            hostname = urlparse(cache.redirects[-1]).hostname
        else:
            hostname = urlparse(cache.url).hostname

        if not hostname:
            return {'error': 'No hostname found.'}

        self.pdns_lookup(hostname, force)
        return {'success': 'Module triggered'}

    def pdns_lookup(self, hostname: str, force: bool=False) -> None:
        '''Lookup an hostname on CIRCL Passive DNS
        Note: force means re-fetch the entry even if we already did it today
        '''
        if not self.available:
            raise ConfigError('CIRCL Passive DNS not available, probably no API key')

        url_storage_dir = get_cache_directory(self.storage_dir_pypdns, hostname, 'pdns')
        url_storage_dir.mkdir(parents=True, exist_ok=True)
        pypdns_file = url_storage_dir / date.today().isoformat()

        if not force and pypdns_file.exists():
            return

        pdns_info = [entry for entry in self.pypdns.iter_query(hostname)]
        if not pdns_info:
            try:
                url_storage_dir.rmdir()
            except OSError:
                # Not empty.
                pass
            return
        pdns_info_store = [entry.raw for entry in sorted(pdns_info, key=lambda k: k.time_last_datetime, reverse=True)]
        with pypdns_file.open('w') as _f:
            json.dump(pdns_info_store, _f)
