#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from lookyloo.lookyloo import Lookyloo

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO, datefmt='%I:%M:%S')

if __name__ == '__main__':
    lookyloo = Lookyloo()
    remove_pickles = input('Do you want to remove the pickles? Rebuilding will take a very long time. (y/N)')
    if remove_pickles == 'y':
        lookyloo.rebuild_all()
    else:
        lookyloo.rebuild_cache()
