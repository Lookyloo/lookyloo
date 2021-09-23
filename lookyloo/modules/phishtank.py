#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional, List

from har2tree import CrawledTree
from pyphishtanklookup import PhishtankLookup

from ..exceptions import ConfigError
from ..helpers import get_homedir

# Note: stop doing requests 48 after the capture was intially done.


class Phishtank():

    def __init__(self, config: Dict[str, Any]):
        if not config.get('enabled'):
            self.available = False
            return

        self.available = True
        self.allow_auto_trigger = False
        if config.get('url'):
            self.client = PhishtankLookup(config['url'])
        else:
            self.client = PhishtankLookup()

        if config.get('allow_auto_trigger'):
            self.allow_auto_trigger = True

        self.storage_dir_pt = get_homedir() / 'phishtank'
        self.storage_dir_pt.mkdir(parents=True, exist_ok=True)

    def __get_cache_directory(self, url: str) -> Path:
        m = hashlib.md5()
        m.update(url.encode())
        return self.storage_dir_pt / m.hexdigest()

    def get_url_lookup(self, url: str) -> Optional[Dict[str, Any]]:
        url_storage_dir = self.__get_cache_directory(url)
        if not url_storage_dir.exists():
            return None
        cached_entries = sorted(url_storage_dir.glob('*'), reverse=True)
        if not cached_entries:
            return None

        with cached_entries[0].open() as f:
            return json.load(f)

    def lookup_ips_capture(self, crawled_tree: CrawledTree) -> Dict[str, List[Dict[str, Any]]]:
        with (crawled_tree.root_hartree.har.path.parent / 'ips.json').open() as f:
            ips_dump = json.load(f)
        to_return: Dict[str, List[Dict[str, Any]]] = {}
        for ip in set(ip for ips_list in ips_dump.values() for ip in ips_list):
            entry = self.get_ip_lookup(ip)
            if not entry:
                continue
            to_return[ip] = []
            for url in entry['urls']:
                entry = self.get_url_lookup(url)
                if entry:
                    to_return[ip].append(entry)
        return to_return

    def get_ip_lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        ip_storage_dir = self.__get_cache_directory(ip)
        if not ip_storage_dir.exists():
            return None
        cached_entries = sorted(ip_storage_dir.glob('*'), reverse=True)
        if not cached_entries:
            return None

        with cached_entries[0].open() as f:
            return json.load(f)

    def capture_default_trigger(self, crawled_tree: CrawledTree, /, *, auto_trigger: bool=False) -> Dict:
        '''Run the module on all the nodes up to the final redirect'''
        if not self.available:
            return {'error': 'Module not available'}
        if auto_trigger and not self.allow_auto_trigger:
            return {'error': 'Auto trigger not allowed on module'}

        # Quit if the capture is more than 70h old, the data in phishtank expire around that time.
        if crawled_tree.start_time <= datetime.now(timezone.utc) - timedelta(hours=70):
            return {'error': 'Capture to old, the response will be irrelevant.'}

        # Check URLs up to the redirect
        if crawled_tree.redirects:
            for redirect in crawled_tree.redirects:
                self.url_lookup(redirect)
        else:
            self.url_lookup(crawled_tree.root_hartree.har.root_url)

        # Check all the IPs in the ips file of the capture
        with (crawled_tree.root_hartree.har.path.parent / 'ips.json').open() as f:
            ips_dump = json.load(f)
        for ip in set(ip for ips_list in ips_dump.values() for ip in ips_list):
            self.ip_lookup(ip)
        return {'success': 'Module triggered'}

    def ip_lookup(self, ip: str) -> None:
        '''Lookup for the URLs related to an IP on Phishtank lookup
        Note: It will trigger a request to phishtank every time *until* there is a hit (it's cheap), then once a day.
        '''
        if not self.available:
            raise ConfigError('Phishtank not available, probably not enabled.')

        ip_storage_dir = self.__get_cache_directory(ip)
        ip_storage_dir.mkdir(parents=True, exist_ok=True)
        pt_file = ip_storage_dir / date.today().isoformat()

        if pt_file.exists():
            return

        urls = self.client.get_urls_by_ip(ip)
        if not urls:
            return
        to_dump = {'ip': ip, 'urls': urls}
        with pt_file.open('w') as _f:
            json.dump(to_dump, _f)
        for url in urls:
            self.url_lookup(url)

    def url_lookup(self, url: str) -> None:
        '''Lookup an URL on Phishtank lookup
        Note: It will trigger a request to phishtank every time *until* there is a hit (it's cheap), then once a day.
        '''
        if not self.available:
            raise ConfigError('Phishtank not available, probably not enabled.')

        url_storage_dir = self.__get_cache_directory(url)
        url_storage_dir.mkdir(parents=True, exist_ok=True)
        pt_file = url_storage_dir / date.today().isoformat()

        if pt_file.exists():
            return

        url_information = self.client.get_url_entry(url)
        if url_information:
            with pt_file.open('w') as _f:
                json.dump(url_information, _f)
