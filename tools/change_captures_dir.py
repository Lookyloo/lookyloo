#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime
from pathlib import Path

from redis import Redis

from lookyloo.helpers import get_captures_dir, safe_create_dir, get_socket_path


def rename_captures():
    r = Redis(unix_socket_path=get_socket_path('cache'))
    capture_dir: Path = get_captures_dir()
    for uuid_path in capture_dir.glob('*/uuid'):
        with uuid_path.open() as f:
            uuid = f.read()
            dir_key = r.hget('lookup_dirs', uuid)
            if dir_key:
                r.hdel('lookup_dirs', uuid)
                r.delete(dir_key)
        timestamp = datetime.strptime(uuid_path.parent.name, '%Y-%m-%dT%H:%M:%S.%f')
        dest_dir = capture_dir / str(timestamp.year) / f'{timestamp.month:02}'
        safe_create_dir(dest_dir)
        uuid_path.parent.rename(dest_dir / uuid_path.parent.name)


if __name__ == '__main__':
    rename_captures()
