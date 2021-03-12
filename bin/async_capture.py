#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging

from lookyloo.abstractmanager import AbstractManager
from lookyloo.helpers import set_running, unset_running, shutdown_requested
from lookyloo.lookyloo import Lookyloo

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO, datefmt='%I:%M:%S')


class AsyncCapture(AbstractManager):

    def __init__(self, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        self.lookyloo = Lookyloo()

    def _to_run_forever(self):
        set_running('async_capture')
        while True:
            url = self.lookyloo.process_capture_queue()
            if url is None or shutdown_requested():
                break
        unset_running('async_capture')


def main():
    m = AsyncCapture()
    m.run(sleep_in_sec=1)


if __name__ == '__main__':
    main()
