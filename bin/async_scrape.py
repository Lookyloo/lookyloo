#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import logging

from lookyloo.abstractmanager import AbstractManager
from lookyloo.helpers import get_homedir, get_socket_path
from lookyloo import scrape
from redis import Redis

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO, datefmt='%I:%M:%S')


class AsyncScraper(AbstractManager):

    def __init__(self, storage_directory: Path=None, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        if not storage_directory:
            self.storage_directory = get_homedir() / 'scraped'
        self.redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)

    def _to_run_forever(self):
        uuid = self.redis.spop('to_scrape')
        if not uuid:
            return
        to_scrape = self.redis.hgetall(uuid)
        to_scrape['perma_uuid'] = uuid
        scrape(**to_scrape)


if __name__ == '__main__':
    m = AsyncScraper()
    m.run(sleep_in_sec=1)
