#!/usr/bin/env python3

'''Geolocation of IP addresses for the web interface (flag + card next to the IPs,
js/components/ip_geo.js), from an mmdb-server instance
(https://github.com/adulau/mmdb-server, ip.circl.lu in the sample config).
A third party service: disabled by default (config/modules.json "IPGeolookup"),
uses the global proxy of Lookyloo. Queried by the server, never by the browser of
the users, with a cache in memory: the same IP is asked once a day at most.
Doc: doc/ui/ip-geolocation.md'''

from __future__ import annotations

import ipaddress
import time

from typing import Any

import requests

from ..helpers import get_useragent_for_requests, global_proxy_for_requests

from .abstractmodule import AbstractModule

CACHE_TTL = 24 * 3600
CACHE_MAX = 10_000
MAX_IPS = 50


class IPGeolookup(AbstractModule):

    def module_init(self) -> bool:
        self.url = str(self.config.get('url') or '').strip()
        if not self.url:
            self.logger.info('No URL configured.')
            return False
        self.session = requests.Session()
        self.session.headers['user-agent'] = get_useragent_for_requests()
        if proxies := global_proxy_for_requests():
            self.session.proxies.update(proxies)
        self._cache: dict[str, tuple[float, dict[str, Any] | None]] = {}
        return True

    @staticmethod
    def _summary(ip: str, answer: Any) -> dict[str, Any] | None:
        '''The useful part of the mmdb-server answer (a list, one entry per database:
        country, country + ASN), and the answer itself for the download.'''
        if not isinstance(answer, list) or not answer:
            return None
        info: dict[str, Any] = {'ip': ip, 'raw': answer}
        for entry in answer:
            if not isinstance(entry, dict):
                continue
            country = entry.get('country') or {}
            details = entry.get('country_info') or {}
            meta = entry.get('meta') or {}
            info.setdefault('iso_code', country.get('iso_code'))
            if details:
                info.setdefault('country', details.get('Country'))
                info.setdefault('alpha3', details.get('Alpha-3 code'))
                info.setdefault('numeric', details.get('Numeric code'))
                info.setdefault('latitude', details.get('Latitude (average)'))
                info.setdefault('longitude', details.get('Longitude (average)'))
            if country.get('AutonomousSystemNumber'):
                info['asn'] = country.get('AutonomousSystemNumber')
                info['as_org'] = country.get('AutonomousSystemOrganization')
            if meta.get('build_db'):
                info.setdefault('sources', []).append({'source': meta.get('db_source'), 'built': meta.get('build_db')})
        return info if info.get('iso_code') or info.get('asn') else None

    def lookup(self, ips: list[str]) -> dict[str, dict[str, Any] | None]:
        '''{ip: summary or None}, for at most MAX_IPS valid global IPs (the others are
        left out: private, loopback... have no geolocation).'''
        if not self.available:
            return {}
        to_return: dict[str, dict[str, Any] | None] = {}
        now = time.time()
        for value in ips[:MAX_IPS]:
            try:
                ip = ipaddress.ip_address(value.strip())
            except ValueError:
                continue
            if not ip.is_global:
                continue
            key = ip.compressed
            if key in self._cache and now - self._cache[key][0] < CACHE_TTL:
                to_return[key] = self._cache[key][1]
                continue
            try:
                response = self.session.get(f'{self.url.rstrip("/")}/{key}', timeout=5)
                response.raise_for_status()
                summary = self._summary(key, response.json())
            except Exception as e:
                self.logger.info(f'Unable to geolocate {key}: {e}')
                continue  # not cached: asked again next time
            if len(self._cache) >= CACHE_MAX:
                self._cache.pop(next(iter(self._cache)))
            self._cache[key] = (now, summary)
            to_return[key] = summary
        return to_return
