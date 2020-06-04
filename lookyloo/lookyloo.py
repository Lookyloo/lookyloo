#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
from collections import defaultdict

from datetime import datetime
from email.message import EmailMessage
from io import BufferedIOBase, BytesIO
import ipaddress
import json
import logging
from pathlib import Path
import pickle
import smtplib
import socket
from typing import Union, Dict, List, Tuple, Optional, Any, MutableMapping, Set
from urllib.parse import urlsplit
from uuid import uuid4
from zipfile import ZipFile

from defang import refang  # type: ignore
from har2tree import CrawledTree, Har2TreeError, HarFile, HostNode, URLNode
from redis import Redis
from scrapysplashwrapper import crawl

from .exceptions import NoValidHarFile, MissingUUID
from .helpers import get_homedir, get_socket_path, load_cookies, load_configs, safe_create_dir, get_email_template
from .modules import VirusTotal, SaneJavaScript


class Lookyloo():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.configs: Dict[str, Dict[str, Any]] = load_configs()
        self.logger.setLevel(self.get_config('loglevel'))

        self.redis: Redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)
        self.scrape_dir: Path = get_homedir() / 'scraped'
        self.splash_url: str = self.get_config('splash_url')
        self.only_global_lookups: bool = self.get_config('only_global_lookups')

        safe_create_dir(self.scrape_dir)

        # Initialize 3rd party components
        if 'modules' not in self.configs:
            self.logger.info('No third party components available in the config directory')
        else:
            if 'VirusTotal' in self.configs['modules']:
                self.vt = VirusTotal(self.configs['modules']['VirusTotal'])
                if not self.vt.available:
                    self.logger.warning('Unable to setup the VirusTotal module')
            if 'SaneJS' in self.configs['modules']:
                self.sanejs = SaneJavaScript(self.configs['modules']['SaneJS'])
                if not self.sanejs.available:
                    self.logger.warning('Unable to setup the SaneJS module')

        if not self.redis.exists('cache_loaded'):
            self._init_existing_dumps()

    def rebuild_cache(self) -> None:
        self.redis.flushdb()
        self._init_existing_dumps()

    def remove_pickle(self, capture_dir: Path) -> None:
        if (capture_dir / 'tree.pickle').exists():
            (capture_dir / 'tree.pickle').unlink()

    def rebuild_all(self) -> None:
        for capture_dir in self.capture_dirs:
            self.remove_pickle(capture_dir)
        self.rebuild_cache()

    def get_config(self, entry: str) -> Any:
        """Get an entry from the generic config file. Automatic fallback to the sample file"""
        if 'generic' in self.configs:
            if entry in self.configs['generic']:
                return self.configs['generic'][entry]
            else:
                self.logger.warning(f'Unable to find {entry} in config file.')
        else:
            self.logger.warning('No generic config file available.')
        self.logger.warning('Falling back on sample config, please initialize the generic config file.')
        with (get_homedir() / 'config' / 'generic.json.sample').open() as _c:
            sample_config = json.load(_c)
        return sample_config[entry]

    def get_urlnode_from_tree(self, capture_dir: Path, node_uuid: str) -> URLNode:
        ct = self._load_pickle(capture_dir / 'tree.pickle')
        if not ct:
            raise MissingUUID(f'Unable to find UUID {node_uuid} in {capture_dir}')
        return ct.root_hartree.get_url_node_by_uuid(node_uuid)

    def get_hostnode_from_tree(self, capture_dir: Path, node_uuid: str) -> HostNode:
        ct = self._load_pickle(capture_dir / 'tree.pickle')
        if not ct:
            raise MissingUUID(f'Unable to find UUID {node_uuid} in {capture_dir}')
        return ct.root_hartree.get_host_node_by_uuid(node_uuid)

    def get_statistics(self, capture_dir: Path) -> Dict[str, Any]:
        # We need the pickle
        ct = self._load_pickle(capture_dir / 'tree.pickle')
        if not ct:
            self.logger.warning(f'Unable to trigger the modules unless the tree ({capture_dir}) is cached.')
            return {}
        return ct.root_hartree.stats

    def trigger_modules(self, capture_dir: Path, force: bool=False) -> None:
        # We need the pickle
        ct = self._load_pickle(capture_dir / 'tree.pickle')
        if not ct:
            self.logger.warning(f'Unable to trigger the modules unless the tree ({capture_dir}) is cached.')
            return

        if hasattr(self, 'vt') and self.vt.available:
            if ct.redirects:
                for redirect in ct.redirects:
                    self.vt.url_lookup(redirect, force)
            else:
                self.vt.url_lookup(ct.root_hartree.har.first_url, force)

    def get_modules_responses(self, capture_dir: Path) -> Optional[Dict[str, Any]]:
        ct = self._load_pickle(capture_dir / 'tree.pickle')
        if not ct:
            self.logger.warning(f'Unable to get the modules responses unless the tree ({capture_dir}) is cached.')
            return None
        to_return: Dict[str, Any] = {}
        if hasattr(self, 'vt') and self.vt.available:
            to_return['vt'] = {}
            if ct.redirects:
                for redirect in ct.redirects:
                    to_return['vt'][redirect] = self.vt.get_url_lookup(redirect)
            else:
                to_return['vt'][ct.root_hartree.har.first_url] = self.vt.get_url_lookup(ct.root_hartree.har.first_url)
        return to_return

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
                error_cache['error'] = f'Capture in {capture_dir.name} has an error: {_error.read()}, see https://splash.readthedocs.io/en/stable/scripting-ref.html#splash-go and https://doc.qt.io/qt-5/qnetworkreply.html#NetworkError-enum'
        elif not har_files:
            error_cache['error'] = f'No har files in {capture_dir}'

        if error_cache:
            self.logger.warning(error_cache['error'])
            self.redis.hmset(str(capture_dir), error_cache)
            self.redis.hset('lookup_dirs', uuid, str(capture_dir))
            return

        har = HarFile(har_files[0], uuid)

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

    def capture_cache(self, capture_dir: Path) -> Optional[Dict[str, Any]]:
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

    def lookup_capture_dir(self, uuid: str) -> Union[Path, None]:
        capture_dir = self.redis.hget('lookup_dirs', uuid)
        if capture_dir:
            return Path(capture_dir)
        return None

    def enqueue_scrape(self, query: MutableMapping[str, Any]) -> str:
        perma_uuid = str(uuid4())
        p = self.redis.pipeline()
        for key, value in query.items():
            if isinstance(value, bool):
                # Yes, empty string because that's False.
                query[key] = 1 if value else ''
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

    def send_mail(self, capture_uuid: str, email: str='', comment: str='') -> None:
        if not self.get_config('enable_mail_notification'):
            return

        redirects = ''
        initial_url = ''
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if capture_dir:
            cache = self.capture_cache(capture_dir)
            if cache:
                initial_url = cache['url']
                if 'redirects' in cache and cache['redirects']:
                    redirects = "Redirects:\n"
                    redirects += '\n'.join(cache['redirects'])
                else:
                    redirects = "No redirects."

        email_config = self.get_config('email')
        msg = EmailMessage()
        msg['From'] = email_config['from']
        if email:
            msg['Reply-To'] = email
        msg['To'] = email_config['to']
        msg['Subject'] = email_config['subject']
        body = get_email_template()
        body = body.format(
            recipient=msg['To'].addresses[0].display_name,
            domain=email_config['domain'],
            uuid=capture_uuid,
            initial_url=initial_url,
            redirects=redirects,
            comment=comment,
            sender=msg['From'].addresses[0].display_name,
        )
        msg.set_content(body)
        try:
            s = smtplib.SMTP(email_config['smtp_host'], email_config['smtp_port'])
            s.send_message(msg)
            s.quit()
        except Exception as e:
            logging.exception(e)

    def load_tree(self, capture_dir: Path) -> Tuple[str, str, str, str, Dict[str, str]]:
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
                with open((capture_dir / 'uuid'), 'r') as f:
                    uuid = f.read()
                ct = CrawledTree(har_files, uuid)
                with pickle_file.open('wb') as _p:
                    pickle.dump(ct, _p)
            return ct.to_json(), ct.start_time.isoformat(), ct.user_agent, ct.root_url, meta
        except Har2TreeError as e:
            raise NoValidHarFile(e.message)

    def _get_raw(self, capture_dir: Path, extension: str='*', all_files: bool=True) -> BytesIO:
        all_paths = sorted(list(capture_dir.glob(f'*.{extension}')))
        if not all_files:
            # Only get the first one in the list
            with open(all_paths[0], 'rb') as f:
                return BytesIO(f.read())
        to_return = BytesIO()
        with ZipFile(to_return, 'w') as myzip:
            for path in all_paths:
                if path.name.endswith('pickle'):
                    continue
                myzip.write(path, arcname=f'{capture_dir.name}/{path.name}')
        to_return.seek(0)
        return to_return

    def get_html(self, capture_dir: Path, all_html: bool=False) -> BytesIO:
        return self._get_raw(capture_dir, 'html', all_html)

    def get_cookies(self, capture_dir: Path, all_cookies: bool=False) -> BytesIO:
        return self._get_raw(capture_dir, 'cookies.json', all_cookies)

    def get_screenshot(self, capture_dir: Path, all_images: bool=False) -> BytesIO:
        return self._get_raw(capture_dir, 'png', all_images)

    def get_capture(self, capture_dir: Path) -> BytesIO:
        return self._get_raw(capture_dir)

    def scrape(self, url: str, cookies_pseudofile: Optional[BufferedIOBase]=None,
               depth: int=1, listing: bool=True, user_agent: Optional[str]=None,
               perma_uuid: str=None, os: str=None, browser: str=None) -> Union[bool, str]:
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
                        self.logger.info('Name or service not known')
                        return False
                    if not ipaddress.ip_address(ip).is_global:
                        return False
            else:
                return False

        cookies = load_cookies(cookies_pseudofile)
        if not user_agent:
            # Catch case where the UA is broken on the UI, and the async submission.
            ua: str = self.get_config('default_user_agent')  # type: ignore
        else:
            ua = user_agent
        items = crawl(self.splash_url, url, cookies=cookies, depth=depth, user_agent=ua,
                      log_enabled=True, log_level=self.get_config('splash_loglevel'))
        if not items:
            # broken
            return False
        if not perma_uuid:
            perma_uuid = str(uuid4())
        width = len(str(len(items)))
        dirpath = self.scrape_dir / datetime.now().isoformat()
        safe_create_dir(dirpath)
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

    def get_hostnode_investigator(self, capture_dir: Path, node_uuid: str) -> Tuple[HostNode, List[Dict[str, Any]]]:
        ct = self._load_pickle(capture_dir / 'tree.pickle')
        if not ct:
            raise MissingUUID(f'Unable to find {capture_dir}')
        hostnode = ct.root_hartree.get_host_node_by_uuid(node_uuid)
        if not hostnode:
            raise MissingUUID(f'Unable to find UUID {node_uuid} in {capture_dir}')

        sanejs_lookups: Dict[str, List[str]] = {}
        if hasattr(self, 'sanejs') and self.sanejs.available:
            to_lookup = [url.body_hash for url in hostnode.urls if hasattr(url, 'body_hash')]
            sanejs_lookups = self.sanejs.hashes_lookup(to_lookup)

        urls: List[Dict[str, Any]] = []
        for url in hostnode.urls:
            # For the popup, we need:
            # * https vs http
            # * everything after the domain
            # * the full URL
            to_append: Dict[str, Any] = {
                'encrypted': url.name.startswith('https'),
                'url_path': url.name.split('/', 3)[-1],
                'url_object': url
            }

            # Optional: SaneJS information
            if hasattr(url, 'body_hash') and url.body_hash in sanejs_lookups:
                if sanejs_lookups[url.body_hash]:
                    if isinstance(sanejs_lookups[url.body_hash], list):
                        libname, version, path = sanejs_lookups[url.body_hash][0].split("|")
                        other_files = len(sanejs_lookups[url.body_hash])
                        to_append['sane_js'] = (libname, version, path, other_files)
                    else:
                        # Predefined generic file
                        to_append['sane_js'] = sanejs_lookups[url.body_hash]

            # Optional: Cookies sent to server in request -> map to nodes who set the cookie in response
            if hasattr(url, 'cookies_sent'):
                to_display: Dict[str, Set[Tuple[str, str]]] = defaultdict(set)
                for cookie, contexts in url.cookies_sent.items():
                    if not contexts:
                        # FIXME Locally created?
                        continue
                    for context in contexts:
                        to_display[cookie].add((context['setter'].hostname, context['setter'].hostnode_uuid))
                to_append['cookies_sent'] = to_display

            # Optional: Cookies received from server in response -> map to nodes who send the cookie in request
            if hasattr(url, 'cookies_received'):
                to_display = defaultdict(set)
                for domain, c_received, is_3rd_party in url.cookies_received:
                    for url_node in ct.root_hartree.cookies_sent[c_received]:
                        to_display[c_received].add((url_node.hostname, url_node.hostnode_uuid))
                to_append['cookies_received'] = to_display

            urls.append(to_append)
        return hostnode, urls
