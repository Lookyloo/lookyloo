#!/usr/bin/env python3

import ipaddress
from typing import Dict, Set

import requests

from ..default import ConfigError

from .abstractmodule import AbstractModule


class Cloudflare(AbstractModule):
    '''This module checks if an IP is announced by Cloudflare.'''

    def module_init(self) -> bool:
        # Get IPv4
        try:
            r = requests.get('https://www.cloudflare.com/ips-v4')
            r.raise_for_status()
            ipv4_list = r.text
        except Exception as e:
            self.logger.warning(f'Unable to get Cloudflare IPv4 list: {e}')
            return False
        # Get IPv6
        try:
            r = requests.get('https://www.cloudflare.com/ips-v6')
            r.raise_for_status()
            ipv6_list = r.text
        except Exception as e:
            self.logger.warning(f'Unable to get Cloudflare IPv6 list: {e}')
            return False

        self.v4_list = [ipaddress.ip_network(net) for net in ipv4_list.split('\n')]
        self.v6_list = [ipaddress.ip_network(net) for net in ipv6_list.split('\n')]
        return True

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
