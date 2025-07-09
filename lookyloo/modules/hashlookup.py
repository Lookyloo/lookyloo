#!/usr/bin/env python3

from __future__ import annotations

import json

from typing import TYPE_CHECKING

from pyhashlookup import Hashlookup

from ..default import ConfigError
from ..helpers import get_useragent_for_requests, global_proxy_for_requests

from .abstractmodule import AbstractModule

if TYPE_CHECKING:
    from ..capturecache import CaptureCache


class HashlookupModule(AbstractModule):
    '''This module is a bit different as it will trigger a lookup of all the hashes
    and store the response in the capture directory'''

    def module_init(self) -> bool:
        if not self.config.get('enabled'):
            self.logger.info('Not enabled.')
            return False

        self.client = Hashlookup(self.config.get('url'), useragent=get_useragent_for_requests(),
                                 proxies=global_proxy_for_requests())
        try:
            # Makes sure the webservice is reachable, raises an exception otherwise.
            self.client.info()
            return True
        except Exception as e:
            self.logger.error(f'Hashlookup webservice is not reachable: {e}')
            return False

    def capture_default_trigger(self, cache: CaptureCache, /, *, force: bool,
                                auto_trigger: bool, as_admin: bool) -> dict[str, str]:
        '''Run the module on all the nodes up to the final redirect'''
        if error := super().capture_default_trigger(cache, force=force, auto_trigger=auto_trigger, as_admin=as_admin):
            return error

        store_file = cache.tree.root_hartree.har.path.parent / 'hashlookup.json'
        if store_file.exists():
            return {'success': 'Module triggered'}

        hashes = cache.tree.root_hartree.build_all_hashes('sha1')

        hits_hashlookup = self.hashes_lookup(list(hashes.keys()))
        if hits_hashlookup:
            # we got at least one hit, saving
            with store_file.open('w') as f:
                json.dump(hits_hashlookup, f, indent=2)

        return {'success': 'Module triggered'}

    def hashes_lookup(self, hashes: list[str]) -> dict[str, dict[str, str]]:
        '''Lookup a list of hashes against Hashlookup
        Note: It will trigger a request to hashlookup every time *until* there is a hit, then once a day.
        '''
        if not self.available:
            raise ConfigError('Hashlookup not available, probably not enabled.')

        to_return: dict[str, dict[str, str]] = {}
        for entry in self.client.sha1_bulk_lookup(hashes):
            if 'SHA-1' in entry:
                to_return[entry['SHA-1'].lower()] = entry
        return to_return
