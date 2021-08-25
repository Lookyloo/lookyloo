#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import ipaddress
import json
import logging
import socket

from io import BufferedIOBase
from datetime import datetime
from pathlib import Path
from typing import Union, Dict, Optional, Tuple, List
from urllib.parse import urlsplit
from uuid import uuid4

from defang import refang  # type: ignore
from redis import Redis
from scrapysplashwrapper import crawl

from lookyloo.abstractmanager import AbstractManager
from lookyloo.helpers import (shutdown_requested, splash_status, get_socket_path,
                              load_cookies, safe_create_dir, get_config, get_splash_url,
                              get_captures_dir)
from lookyloo.lookyloo import Lookyloo

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO, datefmt='%I:%M:%S')


class AsyncCapture(AbstractManager):

    def __init__(self, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        self.lookyloo = Lookyloo()
        self.script_name = 'async_capture'
        self.only_global_lookups: bool = get_config('generic', 'only_global_lookups')
        self.capture_dir: Path = get_captures_dir()
        self.splash_url: str = get_splash_url()
        self.redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)

    def process_capture_queue(self) -> Union[bool, None]:
        '''Process a query from the capture queue'''
        if not self.redis.exists('to_capture'):
            return None

        status, message = splash_status()
        if not status:
            self.logger.critical(f'Splash is not running, unable to process the capture queue: {message}')
            return None

        value: Optional[List[Tuple[str, int]]] = self.redis.zpopmax('to_capture')  # type: ignore
        if not value or not value[0]:
            return None
        uuid, score = value[0]
        queue: Optional[str] = self.redis.get(f'{uuid}_mgmt')
        self.redis.sadd('ongoing', uuid)

        lazy_cleanup = self.redis.pipeline()
        lazy_cleanup.delete(f'{uuid}_mgmt')
        if queue:
            # queue shouldn't be none, but if it is, just ignore.
            lazy_cleanup.zincrby('queues', -1, queue)

        to_capture: Dict[str, str] = self.redis.hgetall(uuid)
        to_capture['perma_uuid'] = uuid
        if 'cookies' in to_capture:
            to_capture['cookies_pseudofile'] = to_capture.pop('cookies')

        status = self._capture(**to_capture)  # type: ignore
        lazy_cleanup.srem('ongoing', uuid)
        lazy_cleanup.delete(uuid)
        # make sure to expire the key if nothing was process for a while (= queues empty)
        lazy_cleanup.expire('queues', 600)
        lazy_cleanup.execute()
        if status:
            self.logger.info(f'Processed {to_capture["url"]}')
            return True
        self.logger.warning(f'Unable to capture {to_capture["url"]}')
        return False

    def _capture(self, url: str, *, cookies_pseudofile: Optional[Union[BufferedIOBase, str]]=None,
                 depth: int=1, listing: bool=True, user_agent: Optional[str]=None,
                 referer: str='', proxy: str='', perma_uuid: Optional[str]=None, os: Optional[str]=None,
                 browser: Optional[str]=None, parent: Optional[str]=None) -> Union[bool, str]:
        '''Launch a capture'''
        url = url.strip()
        url = refang(url)
        if not url.startswith('http'):
            url = f'http://{url}'
        if self.only_global_lookups:
            splitted_url = urlsplit(url)
            if splitted_url.netloc:
                if splitted_url.hostname:
                    if splitted_url.hostname.split('.')[-1] != 'onion':
                        try:
                            ip = socket.gethostbyname(splitted_url.hostname)
                        except socket.gaierror:
                            self.logger.info('Name or service not known')
                            return False
                        if not ipaddress.ip_address(ip).is_global:
                            return False
            else:
                return False

        cookies = load_cookies(cookies_pseudofile)
        if not user_agent:
            # Catch case where the UA is broken on the UI, and the async submission.
            ua: str = get_config('generic', 'default_user_agent')
        else:
            ua = user_agent

        if int(depth) > int(get_config('generic', 'max_depth')):
            self.logger.warning(f'Not allowed to capture on a depth higher than {get_config("generic", "max_depth")}: {depth}')
            depth = int(get_config('generic', 'max_depth'))
        if not perma_uuid:
            perma_uuid = str(uuid4())
        self.logger.info(f'Capturing {url}')
        try:
            items = crawl(self.splash_url, url, cookies=cookies, depth=depth, user_agent=ua,
                          referer=referer, proxy=proxy, log_enabled=True, log_level=get_config('generic', 'splash_loglevel'))
        except Exception as e:
            self.logger.critical(f'Something went terribly wrong when capturing {url}.')
            raise e
        if not items:
            # broken
            self.logger.critical(f'Something went terribly wrong when capturing {url}.')
            return False
        width = len(str(len(items)))
        dirpath = self.capture_dir / datetime.now().isoformat()
        safe_create_dir(dirpath)

        if os or browser:
            meta = {}
            if os:
                meta['os'] = os
            if browser:
                meta['browser'] = browser
            with (dirpath / 'meta').open('w') as _meta:
                json.dump(meta, _meta)

        # Write UUID
        with (dirpath / 'uuid').open('w') as _uuid:
            _uuid.write(perma_uuid)

        # Write no_index marker (optional)
        if not listing:
            (dirpath / 'no_index').touch()

        # Write parent UUID (optional)
        if parent:
            with (dirpath / 'parent').open('w') as _parent:
                _parent.write(parent)

        for i, item in enumerate(items):
            if 'error' in item:
                with (dirpath / 'error.txt').open('w') as _error:
                    json.dump(item['error'], _error)

            # The capture went fine
            harfile = item['har']
            png = base64.b64decode(item['png'])
            html = item['html']
            last_redirect = item['last_redirected_url']

            with (dirpath / '{0:0{width}}.har'.format(i, width=width)).open('w') as _har:
                json.dump(harfile, _har)
            with (dirpath / '{0:0{width}}.png'.format(i, width=width)).open('wb') as _img:
                _img.write(png)
            with (dirpath / '{0:0{width}}.html'.format(i, width=width)).open('w') as _html:
                _html.write(html)
            with (dirpath / '{0:0{width}}.last_redirect.txt'.format(i, width=width)).open('w') as _redir:
                _redir.write(last_redirect)

            if 'childFrames' in item:
                child_frames = item['childFrames']
                with (dirpath / '{0:0{width}}.frames.json'.format(i, width=width)).open('w') as _iframes:
                    json.dump(child_frames, _iframes)

            if 'cookies' in item:
                cookies = item['cookies']
                with (dirpath / '{0:0{width}}.cookies.json'.format(i, width=width)).open('w') as _cookies:
                    json.dump(cookies, _cookies)
        self.redis.hset('lookup_dirs', perma_uuid, str(dirpath))
        return perma_uuid

    def _to_run_forever(self):
        while True:
            url = self.process_capture_queue()
            if url is None or shutdown_requested():
                break


def main():
    m = AsyncCapture()
    m.run(sleep_in_sec=1)


if __name__ == '__main__':
    main()
