#!/usr/bin/env python3

import argparse
import shutil

from lookyloo import Lookyloo
from lookyloo.helpers import get_homedir

removed_captures_dir = get_homedir() / 'removed_captures'


def main() -> None:
    parser = argparse.ArgumentParser(description='Remove a capture from the archives.')
    parser.add_argument('capture_uuid', help='The UUID of the capture to remove.')
    args = parser.parse_args()

    lookyloo = Lookyloo()
    if capture_cache := lookyloo.capture_cache(args.capture_uuid):
        removed_captures_dir.mkdir(parents=True, exist_ok=True)
        print(f'Moving {capture_cache.capture_dir} to {removed_captures_dir / capture_cache.capture_dir.name}')
        shutil.move(str(capture_cache.capture_dir), str(removed_captures_dir / capture_cache.capture_dir.name))
    else:
        print(f'Unable to find capture with UUID {args.capture_uuid}.')


if __name__ == '__main__':
    main()
