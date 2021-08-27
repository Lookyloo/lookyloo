#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time

from lookyloo.abstractmanager import AbstractManager


def main():
    AbstractManager.force_shutdown()
    time.sleep(5)
    while True:
        running = AbstractManager.is_running()
        if not running:
            break
        print(running)
        time.sleep(5)


if __name__ == '__main__':
    main()
