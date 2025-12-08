#!/usr/bin/env python3

from __future__ import annotations

import logging
import logging.config
from pathlib import Path

from redis import Redis

from lookyloo import Indexing
from lookyloo.default import AbstractManager, get_config, get_socket_path
from lookyloo.helpers import remove_pickle_tree


logging.config.dictConfig(get_config('logging'))


class BackgroundIndexer(AbstractManager):

    def __init__(self, full: bool=False, loglevel: int | None=None):
        super().__init__(loglevel)
        self.full_indexer = full
        self.indexing = Indexing(full_index=self.full_indexer)
        if self.full_indexer:
            self.script_name = 'background_full_indexer'
        else:
            self.script_name = 'background_indexer'

        # Redis connector so we don't use the one from Lookyloo
        self.redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)

    def _to_run_forever(self) -> None:
        self._check_indexes()

    def _check_indexes(self) -> None:
        if not self.indexing.can_index():
            # There is no reason to run this method in multiple scripts.
            self.logger.info('Indexing already ongoing in another process.')
            return None
        self.logger.info(f'Check {self.script_name}...')
        # NOTE: only get the non-archived captures for now.
        __counter_shutdown = 0
        for uuid, d in self.redis.hscan_iter('lookup_dirs'):
            if not self.full_indexer:
                # If we're not running the full indexer, check if the capture should be indexed.
                if self.redis.hexists(d, 'no_index'):
                    # Capture unindexed
                    continue
            __counter_shutdown += 1
            path = Path(d)
            try:
                self.indexing.index_capture(uuid, path)
            except Exception as e:
                self.logger.warning(f'Error while indexing {uuid}: {e}')
                remove_pickle_tree(path)
            if __counter_shutdown % 10 and self.shutdown_requested():
                self.logger.warning('Shutdown requested, breaking.')
                break
        else:
            self.logger.info('... done.')
        self.indexing.indexing_done()


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
