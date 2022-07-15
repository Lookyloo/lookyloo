#!/usr/bin/env python3

import json

from datetime import date
from typing import Any, Dict

from har2tree import CrawledTree
from passivetotal import AccountClient, DnsRequest, WhoisRequest

from ..default import ConfigError, get_homedir
from ..helpers import get_cache_directory


class RiskIQ():

    def __init__(self, config: Dict[str, Any]):
        if not (config.get('user') and config.get('apikey')):
            self.available = False
            return

        self.available = True
        self.allow_auto_trigger = False
        test_client = AccountClient(username=config.get('user'), api_key=config.get('apikey'))

        # Check account is working
        details = test_client.get_account_details()
        if 'message' in details and details['message'] == 'invalid credentials':
            self.available = False
            raise ConfigError('RiskIQ not available, invalid credentials')
            return

        self.client_dns = DnsRequest(username=config.get('user'), api_key=config.get('apikey'))
        self.client_whois = WhoisRequest(username=config.get('user'), api_key=config.get('apikey'))

        if config.get('allow_auto_trigger'):
            self.allow_auto_trigger = True

        self.storage_dir_riskiq = get_homedir() / 'riskiq'
        self.storage_dir_riskiq.mkdir(parents=True, exist_ok=True)

    def get_passivedns(self, query: str) -> Dict[str, Any]:
        # The query can be IP or Hostname. For now, we only do it on domains.
        url_storage_dir = get_cache_directory(self.storage_dir_riskiq, query, 'pdns')
        print(url_storage_dir)
        if not url_storage_dir.exists():
            return None
        cached_entries = sorted(url_storage_dir.glob('*'), reverse=True)
        if not cached_entries:
            return None

        with cached_entries[0].open() as f:
            return json.load(f)

    def capture_default_trigger(self, crawled_tree: CrawledTree, /, *, force: bool=False, auto_trigger: bool=False) -> Dict:
        '''Run the module on all the nodes up to the final redirect'''
        if not self.available:
            return {'error': 'Module not available'}
        if auto_trigger and not self.allow_auto_trigger:
            return {'error': 'Auto trigger not allowed on module'}

        self.pdns_lookup(crawled_tree.root_hartree.rendered_node.hostname, force)
        return {'success': 'Module triggered'}

    def pdns_lookup(self, hostname: str, force: bool=False) -> None:
        '''Lookup an hostname on RiskIQ Passive DNS
        Note: force means re-fetch the entry RiskIQ even if we already did it today
        '''
        if not self.available:
            raise ConfigError('RiskIQ not available, probably no API key')

        url_storage_dir = get_cache_directory(self.storage_dir_riskiq, hostname, 'pdns')
        url_storage_dir.mkdir(parents=True, exist_ok=True)
        riskiq_file = url_storage_dir / date.today().isoformat()

        if not force and riskiq_file.exists():
            return

        pdns_info = self.client_dns.get_passive_dns(query=hostname)
        print(pdns_info)
        if not pdns_info:
            return
        with riskiq_file.open('w') as _f:
            json.dump(pdns_info, _f)
