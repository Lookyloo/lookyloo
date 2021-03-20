#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging

from lookyloo.abstractmanager import AbstractManager
from lookyloo.helpers import set_running, unset_running
from lookyloo.lookyloo import Lookyloo
from lookyloo.exceptions import NoValidHarFile

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO, datefmt='%I:%M:%S')


class BackgroundIndexer(AbstractManager):

    def __init__(self, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        self.lookyloo = Lookyloo()
        # make sure discarded captures dir exists
        self.discarded_captures_dir = self.lookyloo.capture_dir.parent / 'discarded_captures'
        self.discarded_captures_dir.mkdir(parents=True, exist_ok=True)

    def _to_run_forever(self):
        set_running('background_indexer')
        self._build_missing_pickles()
        self._check_indexes()
        unset_running('background_indexer')

    def _build_missing_pickles(self):
        for uuid_path in self.lookyloo.capture_dir.glob('*/uuid'):
            if (uuid_path.parent / 'tree.pickle').exists():
                continue
            with uuid_path.open() as f:
                uuid = f.read()
            try:
                self.logger.info(f'Build pickle for {uuid}: {uuid_path.parent.name}')
                self.lookyloo.get_crawled_tree(uuid)
            except NoValidHarFile:
                self.logger.warning(f'Unable to build pickle for {uuid}: {uuid_path.parent.name}')
                # The capture is not working, moving it away.
                self.lookyloo.redis.hdel('lookup_dirs', uuid)
                uuid_path.parent.rename(self.discarded_captures_dir / uuid_path.parent.name)

    def _check_indexes(self):
        for cache in self.lookyloo.sorted_capture_cache():
            if cache.incomplete_redirects:
                # FIXME: this is dirty and needs to be moved.
                self.lookyloo._set_capture_cache(cache.capture_dir, force=True)
                cache = self.lookyloo.capture_cache(cache.uuid)  # type: ignore
            if self.lookyloo.is_public_instance and cache.no_index:
                # Capture unindexed
                continue
            p = self.lookyloo.indexing.redis.pipeline()
            p.sismember('indexed_urls', cache.uuid)
            p.sismember('indexed_body_hashes', cache.uuid)
            p.sismember('indexed_cookies', cache.uuid)
            indexed = p.execute()
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
                self.lookyloo.indexing.index_url_capture(ct)
            if not indexed[1]:
                self.logger.info(f'Indexing resources for {cache.uuid}')
                self.lookyloo.indexing.index_body_hashes_capture(ct)
            if not indexed[2]:
                self.logger.info(f'Indexing cookies for {cache.uuid}')
                self.lookyloo.indexing.index_cookies_capture(ct)


def main():
    i = BackgroundIndexer()
    i.run(sleep_in_sec=60)


if __name__ == '__main__':
    main()
