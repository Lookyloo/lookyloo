#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging

from lookyloo.helpers import load_pickle_tree
from lookyloo.lookyloo import Lookyloo, Indexing

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO, datefmt='%I:%M:%S')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Rebuild the redis cache.')
    parser.add_argument('--rebuild_pickles', default=False, action='store_true', help='Delete and rebuild the pickles. Count 20s/pickle, it can take a very long time.')
    args = parser.parse_args()

    lookyloo = Lookyloo()
    if args.rebuild_pickles:
        lookyloo.rebuild_all()
    else:
        lookyloo.rebuild_cache()

    indexing = Indexing()
    indexing.clear_indexes()
    for capture_dir in lookyloo.capture_dirs:
        tree = load_pickle_tree(capture_dir)
        indexing.index_cookies_capture(tree)
        indexing.index_body_hashes_capture(tree)
