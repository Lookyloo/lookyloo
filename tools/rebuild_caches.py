#!/usr/bin/env python3

import csv
import argparse
import logging

from lookyloo import Indexing, Lookyloo
from lookyloo.helpers import get_captures_dir

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO)


def main() -> None:
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

    # Initialize lookup_dirs key
    for index in get_captures_dir().rglob('index'):
        with index.open('r') as _f:
            recent_uuids = {uuid: str(index.parent / dirname) for uuid, dirname in csv.reader(_f) if (index.parent / dirname).exists()}
        if recent_uuids:
            lookyloo.redis.hset('lookup_dirs', mapping=recent_uuids)  # type: ignore[arg-type]

    # This call will rebuild all the caches as needed.
    lookyloo.sorted_capture_cache()


if __name__ == '__main__':
    main()
