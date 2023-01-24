#!/usr/bin/env python3

import json
import logging

from datetime import date, datetime, timedelta
from typing import Any, Dict, Optional, Union, TYPE_CHECKING
from urllib.parse import urlparse

from passivetotal import AccountClient, DnsRequest, WhoisRequest  # type: ignore
from requests import Response

from ..default import ConfigError, get_homedir, get_config
from ..exceptions import ModuleError
from ..helpers import get_cache_directory

if TYPE_CHECKING:
    from ..capturecache import CaptureCache


class RiskIQError(ModuleError):

    def __init__(self, response: Response):
        self.response = response


class RiskIQ():

    def __init__(self, config: Dict[str, Any]):
        if not (config.get('user') and config.get('apikey')):
            self.available = False
            return

        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))

        self.available = True
        self.allow_auto_trigger = False

        try:
            # Check if account is working
            test_client = AccountClient(username=config.get('user'), api_key=config.get('apikey'), exception_class=RiskIQError)
            details = test_client.get_account_details()
        except RiskIQError as e:
            self.available = False
            if hasattr(e, 'response'):
                details = e.response.json()
                if 'message' in details:
                    self.logger.warning(f'RiskIQ not available, {details["message"]}')
            self.logger.warning(f'RiskIQ not available: {e}')
            return
        except Exception as e:
            self.available = False
            self.logger.warning(f'RiskIQ not available: {e}')
            return

        self.client_dns = DnsRequest(username=config.get('user'), api_key=config.get('apikey'), exception_class=RiskIQError)
        self.client_whois = WhoisRequest(username=config.get('user'), api_key=config.get('apikey'), exception_class=RiskIQError)

        if config.get('allow_auto_trigger'):
            self.allow_auto_trigger = True

        self.default_first_seen = config.get('default_first_seen_in_days', 5)

        self.storage_dir_riskiq = get_homedir() / 'riskiq'
        self.storage_dir_riskiq.mkdir(parents=True, exist_ok=True)

    def get_passivedns(self, query: str) -> Optional[Dict[str, Any]]:
        # The query can be IP or Hostname. For now, we only do it on domains.
        url_storage_dir = get_cache_directory(self.storage_dir_riskiq, query, 'pdns')
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
        if cache.url.startswith('file'):
            return {'error': 'RiskIQ does not support files.'}

        if cache.redirects:
            hostname = urlparse(cache.redirects[-1]).hostname
        else:
            hostname = urlparse(cache.url).hostname

        if not hostname:
            return {'error': 'No hostname found.'}

        self.pdns_lookup(hostname, force)
        return {'success': 'Module triggered'}

    def pdns_lookup(self, hostname: str, force: bool=False, first_seen: Optional[Union[date, datetime]]=None) -> None:
        '''Lookup an hostname on RiskIQ Passive DNS
        Note: force means re-fetch the entry RiskIQ even if we already did it today
        '''
        if not self.available:
            raise ConfigError('RiskIQ not available, probably no API key')

        if first_seen is None:
            first_seen = date.today() - timedelta(days=self.default_first_seen)
        if isinstance(first_seen, datetime):
            first_seen = first_seen.date()

        url_storage_dir = get_cache_directory(self.storage_dir_riskiq, hostname, 'pdns')
        url_storage_dir.mkdir(parents=True, exist_ok=True)
        riskiq_file = url_storage_dir / date.today().isoformat()

        if not force and riskiq_file.exists():
            return

        pdns_info = self.client_dns.get_passive_dns(query=hostname, start=first_seen.isoformat())
        if not pdns_info:
            try:
                url_storage_dir.rmdir()
            except OSError:
                # Not empty.
                pass
            return
        pdns_info['results'] = sorted(pdns_info['results'], key=lambda k: k['lastSeen'], reverse=True)
        with riskiq_file.open('w') as _f:
            json.dump(pdns_info, _f)
