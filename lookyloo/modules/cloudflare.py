#!/usr/bin/env python3

from __future__ import annotations

import ipaddress
import json
import logging

from datetime import datetime, timedelta, timezone
from dateutil.parser import parse

from ..default import get_homedir, get_config, safe_create_dir, LookylooException
from ..helpers import prepare_global_session


class Cloudflare():
    '''This module checks if an IP is announced by Cloudflare.'''

    def __init__(self, test: bool=False) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.config = get_config('modules', 'Cloudflare')
        if test:
            self.available = True
        else:
            self.available = self.config.get('enabled')

        self.ipv4_list: list[ipaddress.IPv4Network] = []
        self.ipv6_list: list[ipaddress.IPv6Network] = []

        if not self.available:
            return

        self.storage_path = get_homedir() / 'config' / 'cloudflare'
        safe_create_dir(self.storage_path)

        self.ipv4_path = self.storage_path / 'ipv4.txt'
        self.ipv6_path = self.storage_path / 'ipv6.txt'

        if not test and self.config.get('autoupdate'):
            # The webserver is reloaded on a regular basis, which will trigger this call if enabled
            self.fetch_lists(test)

        self.init_lists()

    def fetch_lists(self, test: bool=False) -> None:
        '''Store the Cloudflare IP lists in the storage path, only keep one.'''

        last_updates_path = self.storage_path / 'last_updates.json'
        if not test and last_updates_path.exists():
            trigger_fetch = False
            with last_updates_path.open('r') as f:
                last_updates = json.load(f)
            # Only trigger an GET request if one of the file was updated more than 24 hours ago
            cut_time = datetime.now(timezone.utc) - timedelta(hours=24)
            if 'ipv4' in last_updates:
                if datetime.fromisoformat(last_updates['ipv4']) < cut_time:
                    trigger_fetch = True
            if 'ipv6' in last_updates:
                if datetime.fromisoformat(last_updates['ipv6']) < cut_time:
                    trigger_fetch = True
            if not trigger_fetch:
                return
        else:
            last_updates = {}

        session = prepare_global_session()
        # Get IPv4
        try:
            r = session.get('https://www.cloudflare.com/ips-v4', timeout=2)
            r.raise_for_status()
            ipv4_list = r.text
            if r.headers.get('Last-Modified'):
                last_updates['ipv4'] = parse(r.headers['Last-Modified']).isoformat()
        except Exception as e:
            self.logger.warning(f'Unable to get Cloudflare IPv4 list: {e}')
        with self.ipv4_path.open('w') as f:
            f.write(ipv4_list)

        # Get IPv6
        try:
            r = session.get('https://www.cloudflare.com/ips-v6', timeout=2)
            r.raise_for_status()
            ipv6_list = r.text
            if r.headers.get('Last-Modified'):
                last_updates['ipv6'] = parse(r.headers['Last-Modified']).isoformat()
        except Exception as e:
            self.logger.warning(f'Unable to get Cloudflare IPv6 list: {e}')
        with self.ipv6_path.open('w') as f:
            f.write(ipv6_list)

        with last_updates_path.open('w') as f:
            json.dump(last_updates, f)

    def init_lists(self) -> None:
        '''Return the IPv4 and IPv6 lists as a tuple of lists'''
        if not self.available:
            raise LookylooException('Cloudflare module not available.')

        if self.ipv4_path.exists():
            with self.ipv4_path.open('r') as ipv4_file:
                self.ipv4_list = [ipaddress.IPv4Network(net) for net in ipv4_file.read().strip().split('\n')]
        else:
            self.logger.warning('No IPv4 list available.')

        if self.ipv6_path.exists():
            with self.ipv6_path.open('r') as ipv6_file:
                self.ipv6_list = [ipaddress.IPv6Network(net) for net in ipv6_file.read().strip().split('\n')]
        else:
            self.logger.warning('No IPv6 list available.')

    def ips_lookup(self, ips: set[str]) -> dict[str, bool]:
        '''Lookup a list of IPs. True means it is a known Cloudflare IP'''
        if not self.available:
            raise LookylooException('Cloudflare not available.')

        to_return: dict[str, bool] = {}
        for ip_s, ip_p in [(ip, ipaddress.ip_address(ip)) for ip in ips]:
            if ip_p.version == 4:
                to_return[ip_s] = any(ip_p in net for net in self.ipv4_list)
            else:
                to_return[ip_s] = any(ip_p in net for net in self.ipv6_list)
        return to_return
