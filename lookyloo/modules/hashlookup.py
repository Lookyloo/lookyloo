#!/usr/bin/env python3

import json
from typing import Dict, List

from har2tree import CrawledTree
from pyhashlookup import Hashlookup

from ..default import ConfigError
from ..helpers import get_useragent_for_requests

from .abstractmodule import AbstractModule


class HashlookupModule(AbstractModule):
    '''This module is a bit different as it will trigger a lookup of all the hashes
    and store the response in the capture directory'''

    def module_init(self) -> bool:
        if not self.config.get('enabled'):
            self.logger.info('Not enabled.')
            return False

        if self.config.get('url'):
            self.client = Hashlookup(self.config['url'], useragent=get_useragent_for_requests())
        else:
            self.client = Hashlookup(useragent=get_useragent_for_requests())
        # Makes sure the webservice is reachable, raises an exception otherwise.
        self.client.info()

        self.allow_auto_trigger = bool(self.config.get('allow_auto_trigger', False))
        return True

    def capture_default_trigger(self, crawled_tree: CrawledTree, /, *, auto_trigger: bool=False) -> Dict:
        '''Run the module on all the nodes up to the final redirect'''
        if not self.available:
            return {'error': 'Module not available'}
        if auto_trigger and not self.allow_auto_trigger:
            return {'error': 'Auto trigger not allowed on module'}

        store_file = crawled_tree.root_hartree.har.path.parent / 'hashlookup.json'
        if store_file.exists():
            return {'success': 'Module triggered'}

        hashes = crawled_tree.root_hartree.build_all_hashes('sha1')

        hits_hashlookup = self.hashes_lookup(list(hashes.keys()))
        if hits_hashlookup:
            # we got at least one hit, saving
            with store_file.open('w') as f:
                json.dump(hits_hashlookup, f, indent=2)

        return {'success': 'Module triggered'}

    def hashes_lookup(self, hashes: List[str]) -> Dict[str, Dict[str, str]]:
        '''Lookup a list of hashes against Hashlookup
        Note: It will trigger a request to hashlookup every time *until* there is a hit, then once a day.
        '''
        if not self.available:
            raise ConfigError('Hashlookup not available, probably not enabled.')

        to_return: Dict[str, Dict[str, str]] = {}
        for entry in self.client.sha1_bulk_lookup(hashes):
            if 'SHA-1' in entry:
                to_return[entry['SHA-1'].lower()] = entry
        return to_return
