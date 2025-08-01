#!/usr/bin/env python3

from __future__ import annotations

import json

from datetime import date, datetime, timedelta, timezone
from typing import Any, TYPE_CHECKING

from pyphishtanklookup import PhishtankLookup

from ..default import ConfigError, get_homedir
from ..helpers import get_cache_directory, get_useragent_for_requests, global_proxy_for_requests

if TYPE_CHECKING:
    from ..capturecache import CaptureCache

from .abstractmodule import AbstractModule


class Phishtank(AbstractModule):

    def module_init(self) -> bool:
        if not self.config.get('enabled'):
            self.logger.info('Not enabled.')
            return False

        self.client = PhishtankLookup(self.config.get('url'), useragent=get_useragent_for_requests(),
                                      proxies=global_proxy_for_requests())

        if not self.client.is_up:
            self.logger.warning('Not up.')
            return False

        self.storage_dir_pt = get_homedir() / 'phishtank'
        self.storage_dir_pt.mkdir(parents=True, exist_ok=True)
        return True

    def get_url_lookup(self, url: str) -> dict[str, Any] | None:
        url_storage_dir = get_cache_directory(self.storage_dir_pt, url, 'url')
        if not url_storage_dir.exists():
            return None
        cached_entries = sorted(url_storage_dir.glob('*'), reverse=True)
        if not cached_entries:
            return None

        with cached_entries[0].open() as f:
            return json.load(f)

    def lookup_ips_capture(self, cache: CaptureCache) -> dict[str, list[dict[str, Any]]]:
        ips_file = cache.capture_dir / 'ips.json'
        if not ips_file.exists():
            return {}
        with ips_file.open() as f:
            ips_dump = json.load(f)
        to_return: dict[str, list[dict[str, Any]]] = {}
        for ip in {ip for ips_list in ips_dump.values() for ip in ips_list}:
            entry = self.get_ip_lookup(ip)
            if not entry:
                continue
            to_return[ip] = []
            for url in entry['urls']:
                entry = self.get_url_lookup(url)
                if entry:
                    to_return[ip].append(entry)
        return to_return

    def get_ip_lookup(self, ip: str) -> dict[str, Any] | None:
        ip_storage_dir = get_cache_directory(self.storage_dir_pt, ip, 'ip')
        if not ip_storage_dir.exists():
            return None
        cached_entries = sorted(ip_storage_dir.glob('*'), reverse=True)
        if not cached_entries:
            return None

        with cached_entries[0].open() as f:
            return json.load(f)

    def capture_default_trigger(self, cache: CaptureCache, /, *, force: bool,
                                auto_trigger: bool, as_admin: bool) -> dict[str, str]:
        '''Run the module on all the nodes up to the final redirect'''
        if error := super().capture_default_trigger(cache, force=force, auto_trigger=auto_trigger, as_admin=as_admin):
            return error

        # Quit if the capture is more than 70h old, the data in phishtank expire around that time.
        if cache.timestamp <= datetime.now(timezone.utc) - timedelta(hours=70):
            return {'error': 'Capture to old, the response will be irrelevant.'}

        # Check URLs up to the redirect
        if cache.redirects:
            for redirect in cache.redirects:
                self.__url_lookup(redirect)
        else:
            self.__url_lookup(cache.url)

        # Check all the IPs in the ips file of the capture
        ips_file = cache.capture_dir / 'ips.json'
        if not ips_file.exists():
            return {'error': 'No IP file found in the capture'}
        with ips_file.open() as f:
            ips_dump = json.load(f)
        for ip in {ip for ips_list in ips_dump.values() for ip in ips_list}:
            self.__ip_lookup(ip)
        return {'success': 'Module triggered'}

    def __ip_lookup(self, ip: str) -> None:
        '''Lookup for the URLs related to an IP on Phishtank lookup
        Note: It will trigger a request to phishtank every time *until* there is a hit (it's cheap), then once a day.
        '''
        if not self.available:
            raise ConfigError('Phishtank not available, probably not enabled.')

        ip_storage_dir = get_cache_directory(self.storage_dir_pt, ip, 'ip')
        ip_storage_dir.mkdir(parents=True, exist_ok=True)
        pt_file = ip_storage_dir / date.today().isoformat()

        if pt_file.exists():
            return

        urls = self.client.get_urls_by_ip(ip)
        if not urls:
            try:
                ip_storage_dir.rmdir()
            except OSError:
                # no need to print an exception.
                pass
            return
        to_dump = {'ip': ip, 'urls': urls}
        with pt_file.open('w') as _f:
            json.dump(to_dump, _f)
        for url in urls:
            self.__url_lookup(url)

    def __url_lookup(self, url: str) -> None:
        '''Lookup an URL on Phishtank lookup
        Note: It will trigger a request to phishtank every time *until* there is a hit (it's cheap), then once a day.
        '''
        if not self.available:
            raise ConfigError('Phishtank not available, probably not enabled.')

        url_storage_dir = get_cache_directory(self.storage_dir_pt, url, 'url')
        url_storage_dir.mkdir(parents=True, exist_ok=True)
        pt_file = url_storage_dir / date.today().isoformat()

        if pt_file.exists():
            return

        url_information = self.client.get_url_entry(url)
        if not url_information:
            try:
                url_storage_dir.rmdir()
            except OSError:
                # no need to print an exception.
                pass
            return

        with pt_file.open('w') as _f:
            json.dump(url_information, _f)
