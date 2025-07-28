#!/usr/bin/env python3

from __future__ import annotations

import json

from datetime import date
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from pypdns import PyPDNS, PDNSRecord, PDNSError, UnauthorizedError

from ..default import ConfigError, get_homedir
from ..helpers import get_cache_directory, get_useragent_for_requests, global_proxy_for_requests

if TYPE_CHECKING:
    from ..capturecache import CaptureCache

from .abstractmodule import AbstractModule


class CIRCLPDNS(AbstractModule):

    def module_init(self) -> bool:
        if not (self.config.get('user') and self.config.get('password')):
            self.logger.info('Missing credentials.')
            return False

        self.pypdns = PyPDNS(basic_auth=(self.config['user'],
                                         self.config['password']),
                             useragent=get_useragent_for_requests(),
                             proxies=global_proxy_for_requests(),
                             # Disable active query because it should already have been done.
                             disable_active_query=True)

        self.storage_dir_pypdns = get_homedir() / 'circl_pypdns'
        self.storage_dir_pypdns.mkdir(parents=True, exist_ok=True)
        return True

    def _get_live_passivedns(self, query: str) -> list[PDNSRecord]:
        # No cache, just get the records.
        return [entry for entry in self.pypdns.iter_query(query) if isinstance(entry, PDNSRecord)]

    def get_passivedns(self, query: str, live: bool=False) -> list[PDNSRecord] | None:
        if live:
            return self._get_live_passivedns(query)
        # The query can be IP or Hostname. For now, we only do it on domains.
        url_storage_dir = get_cache_directory(self.storage_dir_pypdns, query, 'pdns')
        if not url_storage_dir.exists():
            return None
        cached_entries = sorted(url_storage_dir.glob('*'), reverse=True)
        if not cached_entries:
            return None

        with cached_entries[0].open() as f:
            return [PDNSRecord(record) for record in json.load(f)]

    def capture_default_trigger(self, cache: CaptureCache, /, *, force: bool,
                                auto_trigger: bool, as_admin: bool) -> dict[str, str]:
        '''Run the module on all the nodes up to the final redirect'''
        if error := super().capture_default_trigger(cache, force=force, auto_trigger=auto_trigger, as_admin=as_admin):
            return error
        alreay_done = set()
        for redirect in cache.redirects:
            parsed = urlparse(redirect)
            if parsed.scheme not in ['http', 'https']:
                continue
            if hostname := urlparse(redirect).hostname:
                if hostname in alreay_done:
                    continue
                self.__pdns_lookup(hostname, force)
                alreay_done.add(hostname)
        return {'success': 'Module triggered'}

    def __pdns_lookup(self, hostname: str, force: bool=False) -> None:
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

        try:
            pdns_info = [entry for entry in self.pypdns.iter_query(hostname)]
        except UnauthorizedError:
            self.logger.error('Invalid login/password.')
            return
        except PDNSError as e:
            self.loger.error(f'Unexpected error: {e}')
            return
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
