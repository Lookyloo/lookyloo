#!/usr/bin/env python3

'''Geolocation of IP addresses for the web interface (flag + card next to the IPs,
js/components/ip_geo.js), from an mmdb-server instance
(https://github.com/adulau/mmdb-server, ip.circl.lu by default, config:
generic.json "ip_geolookup_url"). Queried by the server, never by the browser of
the users, with a cache in memory: the same IP is asked once a day at most.
Doc: doc/ui/ip-geolocation.md'''

from __future__ import annotations

import ipaddress
import logging
import time

from typing import Any

import requests

from lookyloo.default import get_config

CACHE_TTL = 24 * 3600
CACHE_MAX = 10_000
MAX_IPS = 50

_cache: dict[str, tuple[float, dict[str, Any] | None]] = {}
logger = logging.getLogger('Lookyloo - IP geolookup')


def geolookup_url() -> str:
    return str(get_config('generic', 'ip_geolookup_url') or '').strip()


def enabled() -> bool:
    return bool(geolookup_url())


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


def lookup(ips: list[str]) -> dict[str, dict[str, Any] | None]:
    '''{ip: summary or None}, for at most MAX_IPS valid global IPs (the others are
    left out: private, loopback... have no geolocation).'''
    url = geolookup_url()
    if not url:
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
        if key in _cache and now - _cache[key][0] < CACHE_TTL:
            to_return[key] = _cache[key][1]
            continue
        try:
            response = requests.get(f'{url.rstrip("/")}/{key}', timeout=5)
            response.raise_for_status()
            summary = _summary(key, response.json())
        except Exception as e:
            logger.info(f'Unable to geolocate {key}: {e}')
            continue  # not cached: asked again next time
        if len(_cache) >= CACHE_MAX:
            _cache.pop(next(iter(_cache)))
        _cache[key] = (now, summary)
        to_return[key] = summary
    return to_return
