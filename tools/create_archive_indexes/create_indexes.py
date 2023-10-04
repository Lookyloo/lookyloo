#!/usr/bin/env python3

import csv
import json
import os
import sys

from datetime import date
from pathlib import Path
from typing import List, Dict

import s3fs  # type: ignore

# manual get config file

configfile = Path(os.path.realpath(__file__)).parent.parent.parent / 'config' / 'generic.json'

with configfile.open() as f:
    config = json.load(f)

if not config.get('s3fs') or not config['s3fs'].get('archive_on_s3fs'):
    print('archive not in s3fs')
    sys.exit()

s3fs_config = config['s3fs']['config']

s3 = s3fs.S3FileSystem(key=s3fs_config['key'], secret=s3fs_config['secret'],
                       endpoint_url=s3fs_config['endpoint_url'],
                       config_kwargs={'connect_timeout': 10, 'read_timeout': 900})

bucket_name = s3fs_config['bucket_name']

s3.clear_multipart_uploads(bucket_name)


def _make_dirs_list(root_dir: str) -> List[str]:
    directories = []
    year_now = date.today().year
    while True:
        year_dir = f'{root_dir}/{year_now}'
        if not s3.exists(year_dir):
            # if we do not have a directory with this year, quit the loop
            break
        for month in range(12, 0, -1):
            month_dir = f'{year_dir}/{month:02}'
            if s3.exists(month_dir):
                directories.append(month_dir)
        year_now -= 1
    return directories


archives_directories = _make_dirs_list(bucket_name)

for directory in archives_directories:
    print(f'Processing {directory}')
    s3.invalidate_cache(directory)
    print('Cache invalidated')
    all_captures = s3.ls(directory, detail=False, refresh=True)
    if not all_captures:
        print('No captures in directory')
        continue

    print(f'{directory} contains {len(all_captures)} captures')
    index_file = f'{directory}/index'
    current_index: Dict[str, str] = {}
    print(f'Processing {index_file}')
    if s3.exists(index_file):
        with s3.open(index_file, 'r') as _f:
            current_index = {uuid: dirname for uuid, dirname in csv.reader(_f)
                             if uuid and dirname}

    print(f'Done with {index_file}, has {len(current_index)} entries')
    curent_index_dirs = set(current_index.values())
    new_captures = 0
    for existing_capture in all_captures:
        capture_dir = existing_capture.rsplit('/', 1)[-1]
        if not capture_dir or capture_dir == 'index':
            continue
        if capture_dir not in curent_index_dirs:
            print(f'New: {existing_capture}')
            uuid_path = f'{existing_capture}/uuid'
            if s3.exists(uuid_path):
                uuid = s3.read_text(uuid_path)
                print(uuid)
                current_index[uuid] = capture_dir
                new_captures += 1
            else:
                print(f'Does not exists: {uuid_path}')
    if not new_captures:
        print(f'No new captures in {directory}')
        continue

    print(f'Updating {index_file} with {new_captures} new captures.')
    with s3.open(index_file, 'w') as _f:
        index_writer = csv.writer(_f)
        for uuid, dirname in current_index.items():
            index_writer.writerow([uuid, dirname])
    print(f'Done updating {index_file}')
