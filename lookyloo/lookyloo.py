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

from typing import Union, Dict, List, Tuple, Optional, Any

import logging

from pysanejs import SaneJS
from scrapysplashwrapper import crawl
from har2tree import CrawledTree, Har2TreeError, HarFile

from defang import refang  # type: ignore


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

    def _set_capture_cache(self, capture_dir: Path, force: bool=False) -> None:
        if force or not self.redis.exists(str(capture_dir)):
            # (re)build cache
            pass
        else:
            return

        with (capture_dir / 'uuid').open() as f:
            uuid = f.read().strip()

        har_files = sorted(capture_dir.glob('*.har'))

        error_cache: Dict[str, str] = {}
        if (capture_dir / 'error.txt').exists():
            # Something went wrong
            with (Path(capture_dir) / 'error.txt').open() as _error:
                error_cache['error'] = f'Capture in {capture_dir} has an error: {_error.read()}, see https://splash.readthedocs.io/en/stable/scripting-ref.html#splash-go and https://doc.qt.io/qt-5/qnetworkreply.html#NetworkError-enum'
        elif not har_files:
            error_cache['error'] = f'No har files in {capture_dir}'

        if error_cache:
            self.logger.warning(error_cache['error'])
            self.redis.hmset(str(capture_dir), error_cache)
            self.redis.hset('lookup_dirs', uuid, str(capture_dir))
            return

        har = HarFile(har_files[0])

        redirects = har.initial_redirects
        incomplete_redirects = False
        if redirects and har.need_tree_redirects:
            # load tree from disk, get redirects
            ct = self._load_pickle(capture_dir / 'tree.pickle')
            if ct:
                redirects = ct.redirects
            else:
                # Pickle not available
                incomplete_redirects = True

        cache: Dict[str, Union[str, int]] = {'uuid': uuid,
                                             'title': har.initial_title,
                                             'timestamp': har.initial_start_time,
                                             'url': har.first_url,
                                             'redirects': json.dumps(redirects),
                                             'incomplete_redirects': 1 if incomplete_redirects else 0}
        if (capture_dir / 'no_index').exists():  # If the folders claims anonymity
            cache['no_index'] = 1

        self.redis.hmset(str(capture_dir), cache)
        self.redis.hset('lookup_dirs', uuid, str(capture_dir))

    def capture_cache(self, capture_dir: Path) -> Optional[Dict[str, Union[str, int]]]:
        if self.redis.hget(str(capture_dir), 'incomplete_redirects') == '1':
            # try to rebuild the cache
            self._set_capture_cache(capture_dir, force=True)
        cached = self.redis.hgetall(str(capture_dir))
        if all(key in cached.keys() for key in ['uuid', 'title', 'timestamp', 'url', 'redirects']):
            cached['redirects'] = json.loads(cached['redirects'])
            return cached
        elif 'error' in cached:
            return cached
        else:
            self.logger.warning(f'Cache ({capture_dir}) is invalid: {json.dumps(cached, indent=2)}')
            return None

    def _init_existing_dumps(self) -> None:
        for capture_dir in self.capture_dirs:
            if capture_dir.exists():
                self._set_capture_cache(capture_dir)
        self.redis.set('cache_loaded', 1)

    @property
    def capture_dirs(self) -> List[Path]:
        for capture_dir in self.scrape_dir.iterdir():
            if capture_dir.is_dir() and not capture_dir.iterdir():
                # Cleanup self.scrape_dir of failed runs.
                capture_dir.rmdir()
            if not (capture_dir / 'uuid').exists():
                # Create uuid if missing
                with (capture_dir / 'uuid').open('w') as f:
                    f.write(str(uuid4()))
        return sorted(self.scrape_dir.iterdir(), reverse=True)

    def lookup_capture_dir(self, uuid) -> Union[Path, None]:
        capture_dir = self.redis.hget('lookup_dirs', uuid)
        if capture_dir:
            return Path(capture_dir)
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

    def _load_pickle(self, pickle_file: Path) -> Optional[CrawledTree]:
        if pickle_file.exists():
            with pickle_file.open('rb') as _p:
                return pickle.load(_p)
        return None

    def load_tree(self, capture_dir: Path) -> Tuple[str, dict, str, str, str, dict]:
        har_files = sorted(capture_dir.glob('*.har'))
        pickle_file = capture_dir / 'tree.pickle'
        try:
            meta = {}
            if (capture_dir / 'meta').exists():
                # NOTE: Legacy, the meta file should be present
                with open((capture_dir / 'meta'), 'r') as f:
                    meta = json.load(f)
            ct = self._load_pickle(pickle_file)
            if not ct:
                ct = CrawledTree(har_files)
                with pickle_file.open('wb') as _p:
                    pickle.dump(ct, _p)
            return str(pickle_file), ct.to_json(), ct.start_time.isoformat(), ct.user_agent, ct.root_url, meta
        except Har2TreeError as e:
            raise NoValidHarFile(e.message)

    def cleanup_old_tmpfiles(self):
        for tmpfile in pathlib.Path(tempfile.gettempdir()).glob('lookyloo*'):
            if time.time() - tmpfile.stat().st_atime > 36000:
                tmpfile.unlink()

    def load_image(self, capture_dir: Path) -> BytesIO:
        with open(list(capture_dir.glob('*.png'))[0], 'rb') as f:
            return BytesIO(f.read())

    def sane_js_query(self, sha512: str) -> Dict:
        if self.use_sane_js:
            return self.sanejs.sha512(sha512)
        return {'response': []}

    def scrape(self, url: str, cookies_pseudofile: Optional[BufferedIOBase]=None, depth: int=1, listing: bool=True, user_agent: Optional[str]=None, perma_uuid: str=None,
               os: str=None, browser: str=None) -> Union[bool, str]:
        url = url.strip()
        url = refang(url)
        if not url.startswith('http'):
            url = f'http://{url}'
        if self.only_global_lookups:
            splitted_url = urlsplit(url)
            if splitted_url.netloc:
                if splitted_url.hostname:
                    try:
                        ip = socket.gethostbyname(splitted_url.hostname)
                    except socket.gaierror:
                        self.logger.info(f'Name or service not known')
                        return False
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
            if not listing:  # Write no_index marker
                (dirpath / 'no_index').touch()
            with (dirpath / 'uuid').open('w') as _uuid:
                _uuid.write(perma_uuid)
            if os or browser:
                meta = {}
                if os:
                    meta['os'] = os
                if browser:
                    meta['browser'] = browser
                with (dirpath / 'meta').open('w') as _meta:
                    json.dump(meta, _meta)
            if 'error' in item:
                with (dirpath / 'error.txt').open('w') as _error:
                    _error.write(item['error'])
                continue

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

        self._set_capture_cache(dirpath)
        return perma_uuid
