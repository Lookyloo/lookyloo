#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import logging

from lookyloo.abstractmanager import AbstractManager
from lookyloo.helpers import get_homedir, set_running, unset_running, shutdown_requested
from lookyloo.lookyloo import Lookyloo

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO, datefmt='%I:%M:%S')


class AsyncScraper(AbstractManager):

    def __init__(self, storage_directory: Path=None, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        if not storage_directory:
            self.storage_directory = get_homedir() / 'scraped'
        self.lookyloo = Lookyloo(loglevel=loglevel)

    def _to_run_forever(self):
        set_running('async_scrape')
        while True:
            url = self.lookyloo.process_scrape_queue()
            if url is None or shutdown_requested():
                break
        unset_running('async_scrape')


if __name__ == '__main__':
    m = AsyncScraper()
    m.run(sleep_in_sec=1)
