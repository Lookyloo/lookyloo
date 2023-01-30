#!/usr/bin/env python3

import ipaddress
import logging
from typing import Dict, Set

import requests

from ..default import ConfigError, get_config


class Cloudflare():
    '''This module checks if an IP is announced by Cloudflare.'''

    def __init__(self):
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))

        # Get IPv4
        r = requests.get('https://www.cloudflare.com/ips-v4')
        try:
            r.raise_for_status()
            ipv4_list = r.text
        except Exception as e:
            self.logger.warning(f'Unable to get Cloudflare IPv4 list: {e}')
            self.available = False
            return
        # Get IPv6
        try:
            r = requests.get('https://www.cloudflare.com/ips-v6')
            ipv6_list = r.text
        except Exception as e:
            self.logger.warning(f'Unable to get Cloudflare IPv6 list: {e}')
            self.available = False
            return

        self.available = True

        self.v4_list = [ipaddress.ip_network(net) for net in ipv4_list.split('\n')]
        self.v6_list = [ipaddress.ip_network(net) for net in ipv6_list.split('\n')]

    def ips_lookup(self, ips: Set[str]) -> Dict[str, bool]:
        '''Lookup a list of IPs. True means it is a known Cloudflare IP'''
        if not self.available:
            raise ConfigError('Hashlookup not available, probably not enabled.')

        to_return: Dict[str, bool] = {}
        for ip_s, ip_p in [(ip, ipaddress.ip_address(ip)) for ip in ips]:
            if ip_p.version == 4:
                to_return[ip_s] = any(ip_p in net for net in self.v4_list)
            else:
                to_return[ip_s] = any(ip_p in net for net in self.v6_list)
        return to_return
