#!/usr/bin/env python3

from __future__ import annotations

import logging
import logging.config

from lookyloo import Lookyloo, Indexing
from lookyloo.default import AbstractManager, get_config
from lookyloo.exceptions import NoValidHarFile


logging.config.dictConfig(get_config('logging'))


class BackgroundIndexer(AbstractManager):

    def __init__(self, full: bool=False, loglevel: int | None=None):
        super().__init__(loglevel)
        self.lookyloo = Lookyloo()
        self.full_indexer = full
        self.indexing = Indexing(full_index=self.full_indexer)
        if self.full_indexer:
            self.script_name = 'background_full_indexer'
        else:
            self.script_name = 'background_indexer'

    def _to_run_forever(self) -> None:
        self._check_indexes()
        # Don't need the cache in this class.
        self.lookyloo.clear_tree_cache()

    def _check_indexes(self) -> None:
        if not self.indexing.can_index:
            # There is no reason to run this method in multiple scripts.
            self.logger.info('Indexing already ongoing in another process.')
            return None
        self.logger.info(f'Check {self.script_name}...')
        for cache in self.lookyloo.sorted_capture_cache(cached_captures_only=False):
            if not self.full_indexer:
                # If we're not running the full indexer, check if the capture should be indexed.
                if self.lookyloo.is_public_instance and cache.no_index:
                    # Capture unindexed
                    continue
            if not cache.tree_ready:
                # pickle isn't ready, we can't index.
                continue
            indexed = self.indexing.capture_indexed(cache.uuid)
            if all(indexed):
                continue
            try:
                ct = self.lookyloo.get_crawled_tree(cache.uuid)
            except NoValidHarFile:
                self.logger.warning(f'Broken pickle for {cache.uuid}')
                self.lookyloo.remove_pickle(cache.uuid)
                continue

            if not indexed[0]:
                self.logger.info(f'Indexing urls for {cache.uuid}')
                self.indexing.index_url_capture(ct)
            if not indexed[1]:
                self.logger.info(f'Indexing resources for {cache.uuid}')
                self.indexing.index_body_hashes_capture(ct)
            if not indexed[2]:
                self.logger.info(f'Indexing cookies for {cache.uuid}')
                self.indexing.index_cookies_capture(ct)
            if not indexed[3]:
                self.logger.info(f'Indexing HH Hashes for {cache.uuid}')
                self.indexing.index_http_headers_hashes_capture(ct)
            if not indexed[4]:
                self.logger.info(f'Indexing favicons for {cache.uuid}')
                favicons = self.lookyloo.get_potential_favicons(cache.uuid, all_favicons=True, for_datauri=False)
                self.indexing.index_favicons_capture(cache.uuid, favicons)
            # NOTE: categories aren't taken in account here, should be fixed(?)
            # see indexing.index_categories_capture(capture_uuid, categories)
        self.indexing.indexing_done()
        self.logger.info('... done.')


def main() -> None:
    i = BackgroundIndexer()
    i.run(sleep_in_sec=60)


def main_full_indexer() -> None:
    if not get_config('generic', 'index_everything'):
        raise Exception('Full indexer is disabled.')
    # NOTE: for now, it only indexes the captures that aren't archived.
    #       we will change that later, but for now, it's a good start.
    i = BackgroundIndexer(full=True)
    i.run(sleep_in_sec=60)


if __name__ == '__main__':
    main()
