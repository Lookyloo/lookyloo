#!/usr/bin/env python3

import time

from lookyloo.default import AbstractManager


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
