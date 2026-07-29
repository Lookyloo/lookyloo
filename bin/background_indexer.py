#!/usr/bin/env python3

from __future__ import annotations

import logging
import logging.config
import time

from datetime import timedelta
from pathlib import Path

from redis import Redis

from lookyloo import Indexing
from lookyloo.default import AbstractManager, get_config, get_socket_path
from lookyloo.helpers import remove_pickle_tree


logging.config.dictConfig(get_config('logging'))


class BackgroundIndexer(AbstractManager):

    def __init__(self, full: bool=False, archives: bool=False, loglevel: int | None=None):
        super().__init__(loglevel)
        self.full_indexer = full
        self.index_archives = archives
        self.indexing = Indexing(full_index=self.full_indexer, archives=self.index_archives)
        if self.full_indexer:
            self.script_name = 'background_full_indexer'
        else:
            self.script_name = 'background_indexer'

        if self.index_archives:
            self.lookup_dirs = 'lookup_dirs_archived'
            self.script_name += '_archives'
        else:
            self.lookup_dirs = 'lookup_dirs'

        # Redis connector so we don't use the one from Lookyloo
        self.redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)

        # The timedelta that means the indexing is slow and it is time to disable it on the public interface
        self.indexing_slow_delta = timedelta(minutes=10)

    def _to_run_forever(self) -> None:
        if self._check_indexes(self.lookup_dirs) and not self.indexing.is_slow:
            self._check_indexes('lazy_index')

    def _check_indexes(self, key: str) -> bool:
        if not self.indexing.can_index():
            # There is no reason to run this method in multiple scripts.
            self.logger.info('Indexing already ongoing in another process.')
            return False
        self.logger.info(f'Check {self.script_name}...')
        # NOTE: only get the non-archived captures for now.
        __counter_shutdown = 0
        __counter_shutdown_force = 0
        indexed_all = False

        clock_last_check = time.monotonic()

        for uuid, d in self.redis.hscan_iter(key):
            if key == 'lazy_index':
                # remove uuid
                self.redis.hdel(key, uuid)

            __counter_shutdown_force += 1
            if __counter_shutdown_force % 100 == 0:
                # check the time, if it took more than 10 min to iterate over 100 hashes, it is slow
                new_time = time.monotonic()
                _td = timedelta(seconds=new_time - clock_last_check)
                if _td > self.indexing_slow_delta:
                    # it is slow.
                    if self.indexing.is_slow:
                        self.logger.warning(f'Indexing is still slow ({_td} for 100 UUIDs).')
                    else:
                        self.logger.warning(f'Indexing is slow ({_td} for 100 UUIDs).')
                        self.indexing.set_slow()
                    if key == 'lazy_index':
                        # stop the lazy index if slow
                        self.logger.warning('Too slow, quit lazy index.')
                        break
                else:
                    # all good
                    if self.indexing.is_slow:
                        self.logger.info('Indexing is not slow anymore.')
                    self.indexing.unset_slow()

                clock_last_check = new_time
                if self.shutdown_requested():
                    self.logger.warning('Shutdown requested, breaking.')
                    break

            if not self.full_indexer:
                # If we're not running the full indexer, check if the capture should be indexed.
                if (self.redis.exists(d)  # the cache exits (not expired)
                        and (self.redis.hexists(d, 'no_index')  # non-indexed capture
                             or self.redis.hexists(d, 'private'))):  # private capture
                    continue
            path = Path(d)
            try:
                if self.indexing.index_capture(uuid, path, background=True):
                    __counter_shutdown += 1
            except Exception as e:
                self.logger.warning(f'Error while indexing {uuid}: {e}')
                remove_pickle_tree(path)
            if __counter_shutdown and __counter_shutdown % 100 == 0:
                self.logger.info('Indexed many captures, periodic restart.')
                break
        else:
            self.logger.info('... done.')
            indexed_all = True
        self.indexing.indexing_done()
        return indexed_all


def main() -> None:
    i = BackgroundIndexer()
    i.run(sleep_in_sec=60)


def main_archives() -> None:
    i = BackgroundIndexer(archives=True)
    i.run(sleep_in_sec=60)


def main_full_indexer() -> None:
    if not get_config('generic', 'index_everything'):
        raise Exception('Full indexer is disabled.')
    # NOTE: for now, it only indexes the captures that aren't archived.
    #       we will change that later, but for now, it's a good start.
    i = BackgroundIndexer(full=True)
    i.run(sleep_in_sec=60)


def main_full_indexer_archives() -> None:
    if not get_config('generic', 'index_everything'):
        raise Exception('Full indexer is disabled.')
    # NOTE: for now, it only indexes the captures that aren't archived.
    #       we will change that later, but for now, it's a good start.
    i = BackgroundIndexer(full=True, archives=True)
    i.run(sleep_in_sec=60)


if __name__ == '__main__':
    main()
