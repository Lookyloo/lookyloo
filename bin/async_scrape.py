#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import logging
from typing import Optional

from lookyloo.abstractmanager import AbstractManager
from lookyloo.helpers import get_homedir, set_running, unset_running, shutdown_requested
from lookyloo.lookyloo import Lookyloo

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO, datefmt='%I:%M:%S')


class AsyncScraper(AbstractManager):

    def __init__(self, storage_directory: Optional[Path]=None, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        if not storage_directory:
            self.storage_directory = get_homedir() / 'scraped'
        self.lookyloo = Lookyloo()

    def _to_run_forever(self):
        set_running('async_scrape')
        while True:
            url = self.lookyloo.process_scrape_queue()
            if url is None or shutdown_requested():
                break
        unset_running('async_scrape')


def main():
    m = AsyncScraper()
    m.run(sleep_in_sec=1)


if __name__ == '__main__':
    main()
