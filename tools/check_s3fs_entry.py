#!/usr/bin/env python3

import argparse
import json
import logging

import s3fs  # type: ignore

from lookyloo.default import get_config


def check_path(path: str) -> dict[str, str]:
    s3fs_config = get_config('generic', 's3fs')
    s3fs_client = s3fs.S3FileSystem(key=s3fs_config['config']['key'],
                                    secret=s3fs_config['config']['secret'],
                                    endpoint_url=s3fs_config['config']['endpoint_url'])

    s3fs_bucket = s3fs_config['config']['bucket_name']
    return s3fs_client.info(f'{s3fs_bucket}/{path}')


if __name__ == '__main__':
    logger = logging.getLogger('Lookyloo - S3FS checker')
    parser = argparse.ArgumentParser(description='Check the status of a file/directory on s3fs.')
    parser.add_argument('--path', help='The path to check on s3fs. Should always start with Year/Month.')
    args = parser.parse_args()

    path_info = check_path(args.path)
    print(json.dumps(path_info, indent=2))
