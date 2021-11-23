#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import ipaddress
import json
import logging
import socket
from datetime import datetime
from io import BufferedIOBase
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlsplit

from defang import refang  # type: ignore
from redis import Redis
from scrapysplashwrapper import crawl

from lookyloo.default import AbstractManager, get_config, get_socket_path, safe_create_dir
from lookyloo.helpers import get_captures_dir, get_splash_url, load_cookies, splash_status

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO)


class AsyncCapture(AbstractManager):

    def __init__(self, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        self.script_name = 'async_capture'
        self.only_global_lookups: bool = get_config('generic', 'only_global_lookups')
        self.capture_dir: Path = get_captures_dir()
        self.splash_url: str = get_splash_url()
        self.redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)

    def process_capture_queue(self) -> None:
        '''Process a query from the capture queue'''
        value: Optional[List[Tuple[str, int]]] = self.redis.zpopmax('to_capture')  # type: ignore
        if not value or not value[0]:
            # The queue was consumed by an other process.
            return
        uuid, _score = value[0]
        queue: Optional[str] = self.redis.get(f'{uuid}_mgmt')
        self.redis.sadd('ongoing', uuid)

        lazy_cleanup = self.redis.pipeline()
        lazy_cleanup.delete(f'{uuid}_mgmt')
        if queue:
            # queue shouldn't be none, but if it is, just ignore.
            lazy_cleanup.zincrby('queues', -1, queue)

        to_capture: Dict[str, str] = self.redis.hgetall(uuid)

        if get_config('generic', 'default_public'):
            # By default, the captures are on the index, unless the user mark them as un-listed
            listing = False if ('listing' in to_capture and to_capture['listing'].lower() in ['false', '0', '']) else True
        else:
            # By default, the captures are not on the index, unless the user mark them as listed
            listing = True if ('listing' in to_capture and to_capture['listing'].lower() in ['true', '1']) else False

        # Turn the freetext for the headers into a dict
        headers = {}
        if 'headers' in to_capture:
            for header_line in to_capture['headers'].splitlines():
                if header_line and ':' in header_line:
                    splitted = header_line.split(':', 1)
                    if splitted and len(splitted) == 2:
                        header, h_value = splitted
                        if header and h_value:
                            headers[header.strip()] = h_value.strip()

        self.logger.info(f'Capturing {to_capture["url"]} - {uuid}')
        success, error_message = self._capture(
            to_capture['url'],
            perma_uuid=uuid,
            cookies_pseudofile=to_capture.get('cookies', None),
            depth=int(to_capture.get('depth', 1)),
            listing=listing,
            user_agent=to_capture.get('user_agent', None),
            referer=to_capture.get('referer', None),
            headers=headers if headers else None,
            proxy=to_capture.get('proxy', None),
            os=to_capture.get('os', None),
            browser=to_capture.get('browser', None),
            parent=to_capture.get('parent', None)
        )
        if success:
            self.logger.info(f'Successfully captured {to_capture["url"]} - {uuid}')
        else:
            self.logger.warning(f'Unable to capture {to_capture["url"]} - {uuid}: {error_message}')
            lazy_cleanup.setex(f'error_{uuid}', 36000, f'{error_message} - {to_capture["url"]} - {uuid}')
        lazy_cleanup.srem('ongoing', uuid)
        lazy_cleanup.delete(uuid)
        # make sure to expire the key if nothing was processed for a while (= queues empty)
        lazy_cleanup.expire('queues', 600)
        lazy_cleanup.execute()

    def _capture(self, url: str, *, perma_uuid: str, cookies_pseudofile: Optional[Union[BufferedIOBase, str]]=None,
                 depth: int=1, listing: bool=True, user_agent: Optional[str]=None,
                 referer: Optional[str]=None, headers: Optional[Dict[str, str]]=None, proxy: Optional[str]=None, os: Optional[str]=None,
                 browser: Optional[str]=None, parent: Optional[str]=None) -> Tuple[bool, str]:
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
                            return False, 'Name or service not known.'
                        if not ipaddress.ip_address(ip).is_global:
                            return False, 'Capturing ressources on private IPs is disabled.'
            else:
                return False, 'Unable to find hostname or IP in the query.'

        cookies = load_cookies(cookies_pseudofile)
        if not user_agent:
            # Catch case where the UA is broken on the UI, and the async submission.
            ua: str = get_config('generic', 'default_user_agent')
        else:
            ua = user_agent

        if int(depth) > int(get_config('generic', 'max_depth')):
            self.logger.warning(f'Not allowed to capture on a depth higher than {get_config("generic", "max_depth")}: {depth}')
            depth = int(get_config('generic', 'max_depth'))
        self.logger.info(f'Capturing {url}')
        try:
            items = crawl(self.splash_url, url, cookies=cookies, depth=depth, user_agent=ua,
                          referer=referer, headers=headers, proxy=proxy, log_enabled=True,
                          log_level=get_config('generic', 'splash_loglevel'))
        except Exception as e:
            self.logger.critical(f'Something went terribly wrong when capturing {url}.')
            raise e
        if not items:
            # broken
            self.logger.critical(f'Something went terribly wrong when capturing {url}.')
            return False, f'Something went terribly wrong when capturing {url}.'
        width = len(str(len(items)))
        now = datetime.now()
        dirpath = self.capture_dir / str(now.year) / f'{now.month:02}' / now.isoformat()
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
        return True, 'All good!'

    def _to_run_forever(self):
        while self.redis.exists('to_capture'):
            status, message = splash_status()
            if not status:
                self.logger.critical(f'Splash is not running, unable to process the capture queue: {message}')
                break

            self.process_capture_queue()
            if self.shutdown_requested():
                break


def main():
    m = AsyncCapture()
    m.run(sleep_in_sec=1)


if __name__ == '__main__':
    main()
