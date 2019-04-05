#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from scrapysplashwrapper import crawl
from har2tree import CrawledTree, Har2TreeError
import pickle

from datetime import datetime

import tempfile
import pathlib
import time

from io import BytesIO
import base64
from uuid import uuid4

from pysanejs import SaneJS

from pathlib import Path
from .helpers import get_homedir, get_socket_path
from .exceptions import NoValidHarFile
from redis import Redis

import logging


class Lookyloo():

    def __init__(self, splash_url: str='http://127.0.0.1:8050', loglevel: int=logging.DEBUG):
        self.__init_logger(loglevel)
        self.redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)
        self.scrape_dir = get_homedir() / 'scraped'
        self.splash_url = splash_url
        if not self.scrape_dir.exists():
            self.scrape_dir.mkdir(parents=True, exist_ok=True)

        self._init_existing_dumps()

        # Try to reach sanejs
        self.sanejs = SaneJS()
        if not self.sanejs.is_up:
            self.sanejs = None

    def __init_logger(self, loglevel) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(loglevel)

    def _set_report_cache(self, report_dir: str):
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
        with har_files[0].open() as f:
            j = json.load(f)
            title = j['log']['pages'][0]['title']
            if not title:
                title = '!! No title found !! '
        cache = {'uuid': uuid, 'title': title}
        if (report_dir / 'no_index').exists():  # If the folders claims anonymity
            cache['no_index'] = 1
        if uuid and not self.redis.hexists('lookup_dirs', uuid):
            self.redis.hmset(str(report_dir), cache)
            self.redis.hset('lookup_dirs', uuid, str(report_dir))

    def report_cache(self, report_dir) -> dict:
        if isinstance(report_dir, Path):
            report_dir = str(report_dir)
        return self.redis.hgetall(report_dir)

    def _init_existing_dumps(self):
        for report_dir in self.report_dirs:
            self._set_report_cache(report_dir)

    @property
    def report_dirs(self):
        for report_dir in self.scrape_dir.iterdir():
            if report_dir.is_dir() and not report_dir.iterdir():
                # Cleanup self.scrape_dir of failed runs.
                report_dir.rmdir()
            if not (report_dir / 'uuid').exists():
                # Create uuid if missing
                with (report_dir / 'uuid').open('w') as f:
                    f.write(str(uuid4()))
        return sorted(self.scrape_dir.iterdir(), reverse=True)

    def lookup_report_dir(self, uuid) -> Path:
        report_dir = self.redis.hget('lookup_dirs', uuid)
        if report_dir:
            return Path(report_dir)
        return None

    def enqueue_scrape(self, query: dict):
        perma_uuid = str(uuid4())
        p = self.redis.pipeline()
        p.hmset(perma_uuid, query)
        p.sadd('to_scrape', perma_uuid)
        p.execute()
        return perma_uuid

    def process_scrape_queue(self):
        uuid = self.redis.spop('to_scrape')
        if not uuid:
            return
        to_scrape = self.redis.hgetall(uuid)
        self.redis.delete(uuid)
        to_scrape['perma_uuid'] = uuid
        self.scrape(**to_scrape)

    def load_tree(self, report_dir: Path):
        har_files = sorted(report_dir.glob('*.har'))
        try:
            ct = CrawledTree(har_files)
            ct.find_parents()
            ct.join_trees()
            temp = tempfile.NamedTemporaryFile(prefix='lookyloo', delete=False)
            pickle.dump(ct, temp)
            temp.close()
            return temp.name, ct.to_json(), ct.start_time.isoformat(), ct.user_agent, ct.root_url
        except Har2TreeError as e:
            raise NoValidHarFile(e.message)

    def cleanup_old_tmpfiles(self):
        for tmpfile in pathlib.Path(tempfile.gettempdir()).glob('lookyloo*'):
            if time.time() - tmpfile.stat().st_atime > 36000:
                tmpfile.unlink()

    def load_image(self, report_dir):
        with open(list(report_dir.glob('*.png'))[0], 'rb') as f:
            return BytesIO(f.read())

    def sane_js_query(self, sha512: str):
        if self.sanejs:
            return self.sanejs.sha512(sha512)
        return {'response': []}

    def scrape(self, url, depth: int=1, listing: bool=True, user_agent: str=None, perma_uuid: str=None):
        if not url.startswith('http'):
            url = f'http://{url}'
        items = crawl(self.splash_url, url, depth, user_agent=user_agent, log_enabled=True, log_level='INFO')
        if not items:
            # broken
            pass
        if not perma_uuid:
            perma_uuid = str(uuid4())
        width = len(str(len(items)))
        dirpath = self.scrape_dir / datetime.now().isoformat()
        dirpath.mkdir()
        if not listing:  # Write no_index marker
            (dirpath / 'no_index').touch()
        for i, item in enumerate(items):
            harfile = item['har']
            png = base64.b64decode(item['png'])
            child_frames = item['childFrames']
            html = item['html']
            with (dirpath / '{0:0{width}}.har'.format(i, width=width)).open('w') as f:
                json.dump(harfile, f)
            with (dirpath / '{0:0{width}}.png'.format(i, width=width)).open('wb') as f:
                f.write(png)
            with (dirpath / '{0:0{width}}.html'.format(i, width=width)).open('w') as f:
                f.write(html)
            with (dirpath / '{0:0{width}}.frames.json'.format(i, width=width)).open('w') as f:
                json.dump(child_frames, f)
            with (dirpath / 'uuid').open('w') as f:
                f.write(perma_uuid)
        self._set_report_cache(dirpath)
        return perma_uuid
