#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging

from lookyloo.lookyloo import Lookyloo, Indexing

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO, datefmt='%I:%M:%S')


def main():
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
    for capture_uuid in lookyloo.capture_uuids:
        index = True
        try:
            tree = lookyloo.get_crawled_tree(capture_uuid)
        except Exception as e:
            print(capture_uuid, e)
            continue

        if lookyloo.is_public_instance:
            cache = lookyloo.capture_cache(capture_uuid)
            if cache.get('no_index') is not None:
                index = False

        # NOTE: these methods do nothing if we just generated the pickle
        if index:
            indexing.index_cookies_capture(tree)
            indexing.index_body_hashes_capture(tree)
            indexing.index_url_capture(tree)


if __name__ == '__main__':
    main()
