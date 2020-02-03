#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

import pickle

from datetime import datetime

import tempfile
import pathlib
import time

import ipaddress
import socket
from urllib.parse import urlsplit

from io import BufferedIOBase, BytesIO
import base64
from uuid import uuid4

from pathlib import Path
from .helpers import get_homedir, get_socket_path, load_cookies
from .exceptions import NoValidHarFile
from redis import Redis

from typing import Union, Dict, List, Tuple, Optional

import logging

from pysanejs import SaneJS
from scrapysplashwrapper import crawl
from har2tree import CrawledTree, Har2TreeError, HarFile


class Lookyloo():

    def __init__(self, splash_url: str='http://127.0.0.1:8050', loglevel: int=logging.DEBUG, only_global_lookups: bool=False) -> None:
        self.__init_logger(loglevel)
        self.redis: Redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)
        self.scrape_dir: Path = get_homedir() / 'scraped'
        self.splash_url: str = splash_url
        self.only_global_lookups: bool = only_global_lookups
        if not self.scrape_dir.exists():
            self.scrape_dir.mkdir(parents=True, exist_ok=True)

        if not self.redis.exists('cache_loaded'):
            self._init_existing_dumps()

        # Try to reach sanejs
        self.sanejs = SaneJS()
        if not self.sanejs.is_up:
            self.use_sane_js = False
        else:
            self.use_sane_js = True

    def __init_logger(self, loglevel: int) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(loglevel)

    def _set_report_cache(self, report_dir: Path) -> None:
        if self.redis.exists(str(report_dir)):
            return
        har_files = sorted(report_dir.glob('*.har'))
        if not har_files:
            self.logger.warning(f'No har files in {report_dir}')
            if (report_dir / 'uuid').exists():
                (report_dir / 'uuid').unlink()
            if (report_dir / 'no_index').exists():
                (report_dir / 'no_index').unlink()
            report_dir.rmdir()
            return
        with (report_dir / 'uuid').open() as f:
            uuid = f.read().strip()
        har = HarFile(har_files[0])

        cache: Dict[str, Union[str, int]] = {'uuid': uuid,
                                             'title': har.initial_title,
                                             'timestamp': har.initial_start_time,
                                             'url': har.first_url,
                                             'redirects': json.dumps(har.initial_redirects)}
        if (report_dir / 'no_index').exists():  # If the folders claims anonymity
            cache['no_index'] = 1
        if uuid and not self.redis.exists(str(report_dir)):
            self.redis.hmset(str(report_dir), cache)
            self.redis.hset('lookup_dirs', uuid, str(report_dir))

    def report_cache(self, report_dir: Union[str, Path]) -> Dict:
        if isinstance(report_dir, Path):
            report_dir = str(report_dir)
        cached = self.redis.hgetall(report_dir)
        cached['redirects'] = json.loads(cached['redirects'])
        return cached

    def _init_existing_dumps(self) -> None:
        for report_dir in self.report_dirs:
            if report_dir.exists():
                self._set_report_cache(report_dir)
        self.redis.set('cache_loaded', 1)

    @property
    def report_dirs(self) -> List[Path]:
        for report_dir in self.scrape_dir.iterdir():
            if report_dir.is_dir() and not report_dir.iterdir():
                # Cleanup self.scrape_dir of failed runs.
                report_dir.rmdir()
            if not (report_dir / 'uuid').exists():
                # Create uuid if missing
                with (report_dir / 'uuid').open('w') as f:
                    f.write(str(uuid4()))
        return sorted(self.scrape_dir.iterdir(), reverse=True)

    def lookup_report_dir(self, uuid) -> Union[Path, None]:
        report_dir = self.redis.hget('lookup_dirs', uuid)
        if report_dir:
            return Path(report_dir)
        return None

    def enqueue_scrape(self, query: dict) -> str:
        perma_uuid = str(uuid4())
        p = self.redis.pipeline()
        p.hmset(perma_uuid, query)
        p.sadd('to_scrape', perma_uuid)
        p.execute()
        return perma_uuid

    def process_scrape_queue(self) -> Union[bool, None]:
        uuid = self.redis.spop('to_scrape')
        if not uuid:
            return None
        to_scrape = self.redis.hgetall(uuid)
        self.redis.delete(uuid)
        to_scrape['perma_uuid'] = uuid
        if self.scrape(**to_scrape):
            self.logger.info(f'Processed {to_scrape["url"]}')
            return True
        return False

    def load_tree(self, report_dir: Path) -> Tuple[str, dict, str, str, str, dict]:
        har_files = sorted(report_dir.glob('*.har'))
        try:
            meta = {}
            if (report_dir / 'meta').exists():
                with open((report_dir / 'meta'), 'r') as f:
                    meta = json.load(f)
            ct = CrawledTree(har_files)
            temp = tempfile.NamedTemporaryFile(prefix='lookyloo', delete=False)
            pickle.dump(ct, temp)
            temp.close()
            return temp.name, ct.to_json(), ct.start_time.isoformat(), ct.user_agent, ct.root_url, meta
        except Har2TreeError as e:
            raise NoValidHarFile(e.message)

    def cleanup_old_tmpfiles(self):
        for tmpfile in pathlib.Path(tempfile.gettempdir()).glob('lookyloo*'):
            if time.time() - tmpfile.stat().st_atime > 36000:
                tmpfile.unlink()

    def load_image(self, report_dir: Path) -> BytesIO:
        with open(list(report_dir.glob('*.png'))[0], 'rb') as f:
            return BytesIO(f.read())

    def sane_js_query(self, sha512: str) -> Dict:
        if self.use_sane_js:
            return self.sanejs.sha512(sha512)
        return {'response': []}

    def scrape(self, url: str, cookies_pseudofile: Optional[BufferedIOBase]=None, depth: int=1, listing: bool=True, user_agent: Optional[str]=None, perma_uuid: str=None,
               os: str=None, browser: str=None) -> Union[bool, str]:
        if not url.startswith('http'):
            url = f'http://{url}'
        if self.only_global_lookups:
            splitted_url = urlsplit(url)
            if splitted_url.netloc:
                if splitted_url.hostname:
                    ip = socket.gethostbyname(splitted_url.hostname)
                    if not ipaddress.ip_address(ip).is_global:
                        return False
            else:
                return False

        cookies = load_cookies(cookies_pseudofile)
        items = crawl(self.splash_url, url, cookies=cookies, depth=depth, user_agent=user_agent, log_enabled=True, log_level='INFO')
        if not items:
            # broken
            return False
        if not perma_uuid:
            perma_uuid = str(uuid4())
        width = len(str(len(items)))
        dirpath = self.scrape_dir / datetime.now().isoformat()
        dirpath.mkdir()
        for i, item in enumerate(items):
            harfile = item['har']
            png = base64.b64decode(item['png'])

            if 'childFrames' in item:
                child_frames = item['childFrames']
                with (dirpath / '{0:0{width}}.frames.json'.format(i, width=width)).open('w') as _iframes:
                    json.dump(child_frames, _iframes)

            if 'cookies' in item:
                cookies = item['cookies']
                with (dirpath / '{0:0{width}}.cookies.json'.format(i, width=width)).open('w') as _cookies:
                    json.dump(cookies, _cookies)

            html = item['html']
            with (dirpath / '{0:0{width}}.har'.format(i, width=width)).open('w') as _har:
                json.dump(harfile, _har)
            with (dirpath / '{0:0{width}}.png'.format(i, width=width)).open('wb') as _img:
                _img.write(png)
            with (dirpath / '{0:0{width}}.html'.format(i, width=width)).open('w') as _html:
                _html.write(html)
            with (dirpath / 'uuid').open('w') as _uuid:
                _uuid.write(perma_uuid)
            if not listing:  # Write no_index marker
                (dirpath / 'no_index').touch()
            if os or browser:
                meta = {}
                if os:
                    meta['os'] = os
                if browser:
                    meta['browser'] = browser
                with (dirpath / 'meta').open('w') as _meta:
                    json.dump(meta, _meta)
        self._set_report_cache(dirpath)
        return perma_uuid
