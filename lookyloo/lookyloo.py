#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import base64
from collections import defaultdict, Counter

from datetime import datetime, date, timedelta
from email.message import EmailMessage
from io import BufferedIOBase, BytesIO
import ipaddress
import json
import logging
from pathlib import Path
import pickle
import smtplib
import socket
from typing import Union, Dict, List, Tuple, Optional, Any, MutableMapping, Set, Iterable
from urllib.parse import urlsplit
from uuid import uuid4
from zipfile import ZipFile

from defang import refang  # type: ignore
from har2tree import CrawledTree, Har2TreeError, HarFile, HostNode, URLNode
from redis import Redis
from scrapysplashwrapper import crawl

from werkzeug.useragents import UserAgent

from .exceptions import NoValidHarFile, MissingUUID
from .helpers import get_homedir, get_socket_path, load_cookies, load_configs, safe_create_dir, get_email_template, load_pickle_tree, remove_pickle_tree
from .modules import VirusTotal, SaneJavaScript, PhishingInitiative


class Indexing():

    def __init__(self) -> None:
        self.lookyloo = Lookyloo()
        self.redis: Redis = Redis(unix_socket_path=get_socket_path('indexing'), decode_responses=True)

    @property
    def cookies_names(self) -> List[Tuple[str, float]]:
        return self.redis.zrevrange('cookies_names', 0, -1, withscores=True)

    def cookies_names_number_domains(self, cookie_name: str) -> int:
        return self.redis.zcard(f'cn|{cookie_name}')

    def cookies_names_domains_values(self, cookie_name: str, domain: str) -> List[Tuple[str, float]]:
        return self.redis.zrevrange(f'cn|{cookie_name}|{domain}', 0, -1, withscores=True)

    def get_cookie_domains(self, cookie_name: str) -> List[Tuple[str, float]]:
        return self.redis.zrevrange(f'cn|{cookie_name}', 0, -1, withscores=True)

    def get_capture_cache(self, capture_uuid: str) -> Optional[Dict[str, Any]]:
        capture_dir = self.lookyloo.lookup_capture_dir(capture_uuid)
        if capture_dir:
            return self.lookyloo.capture_cache(capture_dir)
        return {}

    def get_cookies_names_captures(self, cookie_name: str) -> List[Tuple[str, str]]:
        return [uuids.split('|')for uuids in self.redis.smembers(f'cn|{cookie_name}|captures')]

    def clear_indexes(self):
        self.redis.flushdb()

    def index_all(self):
        self.index_cookies()

    def index_cookies_capture(self, capture_dir: Path) -> None:
        print(f'Processing {capture_dir}')
        try:
            crawled_tree = self.lookyloo.get_crawled_tree(capture_dir)
        except Exception as e:
            print(e)
            return

        if self.redis.sismember('indexed_cookies', crawled_tree.uuid):
            # Do not reindex
            return
        self.redis.sadd('indexed_cookies', crawled_tree.uuid)

        pipeline = self.redis.pipeline()
        already_loaded: Set[Tuple[str, str]] = set()
        for urlnode in crawled_tree.root_hartree.url_tree.traverse():
            if hasattr(urlnode, 'cookies_received'):
                for domain, cookie, _ in urlnode.cookies_received:
                    name, value = cookie.split('=', 1)
                    if (name, domain) in already_loaded:
                        # Only add cookie name once / capture
                        continue
                    already_loaded.add((name, domain))
                    pipeline.zincrby('cookies_names', 1, name)
                    pipeline.zincrby(f'cn|{name}', 1, domain)
                    pipeline.sadd(f'cn|{name}|captures', f'{crawled_tree.uuid}|{urlnode.uuid}')
                    pipeline.zincrby(f'cn|{name}|{domain}', 1, value)

                    pipeline.sadd('lookyloo_domains', domain)
                    pipeline.sadd(domain, name)
        pipeline.execute()

    def index_cookies(self) -> None:
        for capture_dir in self.lookyloo.capture_dirs:
            self.index_cookies_capture(capture_dir)


class Lookyloo():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.configs: Dict[str, Dict[str, Any]] = load_configs()
        self.logger.setLevel(self.get_config('loglevel'))

        self.redis: Redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)
        self.scrape_dir: Path = get_homedir() / 'scraped'
        if os.environ.get('SPLASH_URL_DOCKER'):
            # In order to have a working default for the docker image, it is easier to use an environment variable
            self.splash_url: str = os.environ['SPLASH_URL_DOCKER']
        else:
            self.splash_url = self.get_config('splash_url')
        self.only_global_lookups: bool = self.get_config('only_global_lookups')

        safe_create_dir(self.scrape_dir)

        # Initialize 3rd party components
        if 'modules' not in self.configs:
            self.logger.info('No third party components available in the config directory')
        else:
            if 'PhishingInitiative' in self.configs['modules']:
                self.pi = PhishingInitiative(self.configs['modules']['PhishingInitiative'])
                if not self.pi.available:
                    self.logger.warning('Unable to setup the PhishingInitiative module')
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

    def cache_user_agents(self, user_agent: str, remote_ip: str) -> None:
        today = date.today().isoformat()
        self.redis.zincrby(f'user_agents|{today}', 1, f'{remote_ip}|{user_agent}')

    def build_ua_file(self) -> None:
        yesterday = (date.today() - timedelta(days=1))
        self_generated_ua_file_path = get_homedir() / 'own_user_agents' / str(yesterday.year) / f'{yesterday.month:02}'
        safe_create_dir(self_generated_ua_file_path)
        self_generated_ua_file = self_generated_ua_file_path / f'{yesterday.isoformat()}.json'
        if self_generated_ua_file.exists():
            return
        entries = self.redis.zrevrange(f'user_agents|{yesterday.isoformat()}', 0, -1)
        if not entries:
            return

        to_store: Dict[str, Any] = {'by_frequency': []}
        uas = Counter([entry.split('|', 1)[1] for entry in entries])
        for ua, count in uas.most_common():
            parsed_ua = UserAgent(ua)
            if not parsed_ua.platform or not parsed_ua.browser:  # type: ignore
                continue
            if parsed_ua.platform not in to_store:  # type: ignore
                to_store[parsed_ua.platform] = {}  # type: ignore
            if f'{parsed_ua.browser} {parsed_ua.version}' not in to_store[parsed_ua.platform]:  # type: ignore
                to_store[parsed_ua.platform][f'{parsed_ua.browser} {parsed_ua.version}'] = []  # type: ignore
            to_store[parsed_ua.platform][f'{parsed_ua.browser} {parsed_ua.version}'].append(parsed_ua.string)  # type: ignore
            to_store['by_frequency'].append({'os': parsed_ua.platform,  # type: ignore
                                             'browser': f'{parsed_ua.browser} {parsed_ua.version}',  # type: ignore
                                             'useragent': parsed_ua.string})  # type: ignore
        with self_generated_ua_file.open('w') as f:
            json.dump(to_store, f, indent=2)

    def cache_tree(self, capture_uuid) -> None:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')

        with open((capture_dir / 'uuid'), 'r') as f:
            uuid = f.read()
        har_files = sorted(capture_dir.glob('*.har'))
        try:
            ct = CrawledTree(har_files, uuid)
        except Har2TreeError as e:
            raise NoValidHarFile(e.message)

        with (capture_dir / 'tree.pickle').open('wb') as _p:
            pickle.dump(ct, _p)

    def get_crawled_tree(self, capture_uuid: str) -> CrawledTree:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        ct = load_pickle_tree(capture_dir)
        if not ct:
            self.cache_tree(capture_uuid)
            ct = load_pickle_tree(capture_dir)

        if not ct:
            raise NoValidHarFile(f'Unable to get tree from {capture_dir}')

        return ct

    def load_tree(self, capture_uuid: str) -> Tuple[str, str, str, str, Dict[str, str]]:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        meta = {}
        if (capture_dir / 'meta').exists():
            with open((capture_dir / 'meta'), 'r') as f:
                meta = json.load(f)
        ct = self.get_crawled_tree(capture_uuid)
        return ct.to_json(), ct.start_time.isoformat(), ct.user_agent, ct.root_url, meta

    def remove_pickle(self, capture_uuid: str) -> None:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        remove_pickle_tree(capture_dir)

    def rebuild_cache(self) -> None:
        self.redis.flushdb()
        self._init_existing_dumps()

    def rebuild_all(self) -> None:
        for capture_dir in self.capture_dirs:
            remove_pickle_tree(capture_dir)
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

    def get_urlnode_from_tree(self, capture_uuid: str, node_uuid: str) -> URLNode:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        ct = load_pickle_tree(capture_dir)
        if not ct:
            raise MissingUUID(f'Unable to find UUID {node_uuid} in {capture_dir}')
        return ct.root_hartree.get_url_node_by_uuid(node_uuid)

    def get_hostnode_from_tree(self, capture_uuid: str, node_uuid: str) -> HostNode:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        ct = load_pickle_tree(capture_dir)
        if not ct:
            raise MissingUUID(f'Unable to find UUID {node_uuid} in {capture_dir}')
        return ct.root_hartree.get_host_node_by_uuid(node_uuid)

    def get_statistics(self, capture_uuid: str) -> Dict[str, Any]:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        ct = load_pickle_tree(capture_dir)
        if not ct:
            self.logger.warning(f'Unable to trigger the modules unless the tree ({capture_dir}) is cached.')
            return {}
        return ct.root_hartree.stats

    def trigger_modules(self, capture_uuid: str, force: bool=False) -> None:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        ct = load_pickle_tree(capture_dir)
        if not ct:
            self.logger.warning(f'Unable to trigger the modules unless the tree ({capture_dir}) is cached.')
            return

        if hasattr(self, 'pi') and self.pi.available:
            if ct.redirects:
                for redirect in ct.redirects:
                    self.pi.url_lookup(redirect, force)
            else:
                self.pi.url_lookup(ct.root_hartree.har.root_url, force)

        if hasattr(self, 'vt') and self.vt.available:
            if ct.redirects:
                for redirect in ct.redirects:
                    self.vt.url_lookup(redirect, force)
            else:
                self.vt.url_lookup(ct.root_hartree.har.root_url, force)

    def get_modules_responses(self, capture_uuid: str) -> Optional[Dict[str, Any]]:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        ct = load_pickle_tree(capture_dir)
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
                to_return['vt'][ct.root_hartree.har.root_url] = self.vt.get_url_lookup(ct.root_hartree.har.root_url)
        if hasattr(self, 'pi') and self.pi.available:
            to_return['pi'] = {}
            if ct.redirects:
                for redirect in ct.redirects:
                    to_return['pi'][redirect] = self.pi.get_url_lookup(redirect)
            else:
                to_return['pi'][ct.root_hartree.har.root_url] = self.pi.get_url_lookup(ct.root_hartree.har.root_url)
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
                content = _error.read()
                try:
                    error_to_cache = json.loads(content)
                    if isinstance(error_to_cache, dict) and error_to_cache.get('details'):
                        error_to_cache = error_to_cache.get('details')
                except json.decoder.JSONDecodeError:
                    # old format
                    error_to_cache = content
                error_cache['error'] = f'The capture {capture_dir.name} has an error: {error_to_cache}'

        fatal_error = False
        if har_files:
            try:
                har = HarFile(har_files[0], uuid)
            except Har2TreeError as e:
                error_cache['error'] = e.message
                fatal_error = True
        else:
            error_cache['error'] = f'No har files in {capture_dir.name}'
            fatal_error = True

        if error_cache:
            self.logger.warning(error_cache['error'])
            self.redis.hmset(str(capture_dir), error_cache)
            self.redis.hset('lookup_dirs', uuid, str(capture_dir))

        if fatal_error:
            return

        redirects = har.initial_redirects
        incomplete_redirects = False
        if redirects and har.need_tree_redirects:
            # load tree from disk, get redirects
            ct = load_pickle_tree(capture_dir)
            if ct:
                redirects = ct.redirects
            else:
                # Pickle not available
                incomplete_redirects = True

        cache: Dict[str, Union[str, int]] = {'uuid': uuid,
                                             'title': har.initial_title,
                                             'timestamp': har.initial_start_time,
                                             'url': har.root_url,
                                             'redirects': json.dumps(redirects),
                                             'capture_dir': str(capture_dir),
                                             'incomplete_redirects': 1 if incomplete_redirects else 0}
        if (capture_dir / 'no_index').exists():  # If the folders claims anonymity
            cache['no_index'] = 1

        self.redis.hmset(str(capture_dir), cache)
        self.redis.hset('lookup_dirs', uuid, str(capture_dir))

    @property
    def capture_uuids(self):
        return self.redis.hkeys('lookup_dirs')

    def capture_cache(self, capture_uuid: str) -> Dict[str, Any]:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        if self.redis.hget(str(capture_dir), 'incomplete_redirects') == '1':
            # try to rebuild the cache
            self._set_capture_cache(capture_dir, force=True)
        cached = self.redis.hgetall(str(capture_dir))
        if all(key in cached.keys() for key in ['uuid', 'title', 'timestamp', 'url', 'redirects', 'capture_dir']):
            cached['redirects'] = json.loads(cached['redirects'])
            cached['capture_dir'] = Path(cached['capture_dir'])
            return cached
        elif 'error' in cached:
            return cached
        else:
            self.logger.warning(f'Cache ({capture_dir}) is invalid: {json.dumps(cached, indent=2)}')
            return {}

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

    def lookup_capture_dir(self, capture_uuid: str) -> Union[Path, None]:
        capture_dir = self.redis.hget('lookup_dirs', capture_uuid)
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

    def send_mail(self, capture_uuid: str, email: str='', comment: str='') -> None:
        if not self.get_config('enable_mail_notification'):
            return

        redirects = ''
        initial_url = ''
        cache = self.capture_cache(capture_uuid)
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
            self.logger.exception(e)

    def _ensure_meta(self, capture_dir: Path, tree: CrawledTree) -> None:
        metafile = capture_dir / 'meta'
        if metafile.exists():
            return
        ua = UserAgent(tree.root_hartree.user_agent)
        to_dump = {}
        if ua.platform:  # type: ignore
            to_dump['os'] = ua.platform  # type: ignore
        if ua.browser:  # type: ignore
            if ua.version:  # type: ignore
                to_dump['browser'] = f'{ua.browser} {ua.version}'  # type: ignore
            else:
                to_dump['browser'] = ua.browser  # type: ignore
        if ua.language:  # type: ignore
            to_dump['language'] = ua.language  # type: ignore

        if not to_dump:
            # UA not recognized
            self.logger.info(f'Unable to recognize the User agent: {ua}')
        to_dump['user_agent'] = ua.string  # type: ignore
        with metafile.open('w') as f:
            json.dump(to_dump, f)

    def _get_raw(self, capture_uuid: str, extension: str='*', all_files: bool=True) -> BytesIO:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
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

    def get_html(self, capture_uuid: str, all_html: bool=False) -> BytesIO:
        return self._get_raw(capture_uuid, 'html', all_html)

    def get_cookies(self, capture_uuid: str, all_cookies: bool=False) -> BytesIO:
        return self._get_raw(capture_uuid, 'cookies.json', all_cookies)

    def get_screenshot(self, capture_uuid: str, all_images: bool=False) -> BytesIO:
        return self._get_raw(capture_uuid, 'png', all_images)

    def get_capture(self, capture_uuid: str) -> BytesIO:
        return self._get_raw(capture_uuid)

    def scrape(self, url: str, cookies_pseudofile: Optional[BufferedIOBase]=None,
               depth: int=1, listing: bool=True, user_agent: Optional[str]=None,
               referer: Optional[str]=None, perma_uuid: str=None, os: str=None,
               browser: str=None) -> Union[bool, str]:
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

        if int(depth) > int(self.get_config('max_depth')):  # type: ignore
            self.logger.warning(f'Not allowed to scrape on a depth higher than {self.get_config("max_depth")}: {depth}')
            depth = int(self.get_config('max_depth'))  # type: ignore
        items = crawl(self.splash_url, url, cookies=cookies, depth=depth, user_agent=ua,
                      referer=referer, log_enabled=True, log_level=self.get_config('splash_loglevel'))
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

        self._set_capture_cache(dirpath)
        return perma_uuid

    def get_hostnode_investigator(self, capture_uuid: str, node_uuid: str) -> Tuple[HostNode, List[Dict[str, Any]]]:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find {capture_uuid}')

        ct = load_pickle_tree(capture_dir)
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

            # If the url path is too long, we want to limit it to 60 chars
            if len(to_append['url_path']) > 50:
                to_append['url_path_short'] = to_append['url_path'][:60] + ' [...]'
            else:
                to_append['url_path_short'] = to_append['url_path']

            if not url.empty_response:
                # Optional: SaneJS information
                if url.body_hash in sanejs_lookups:
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
                to_display_sent: Dict[str, Set[Iterable[Optional[str]]]] = defaultdict(set)
                for cookie, contexts in url.cookies_sent.items():
                    if not contexts:
                        # Locally created?
                        to_display_sent[cookie].add(('Unknown origin', ))
                        continue
                    for context in contexts:
                        to_display_sent[cookie].add((context['setter'].hostname, context['setter'].hostnode_uuid))
                to_append['cookies_sent'] = to_display_sent

            # Optional: Cookies received from server in response -> map to nodes who send the cookie in request
            if hasattr(url, 'cookies_received'):
                to_display_received: Dict[str, Dict[str, Set[Iterable[Optional[str]]]]] = {'3rd_party': defaultdict(set), 'sent': defaultdict(set), 'not_sent': defaultdict(set)}
                for domain, c_received, is_3rd_party in url.cookies_received:
                    if c_received not in ct.root_hartree.cookies_sent:
                        # This cookie is never sent.
                        if is_3rd_party:
                            to_display_received['3rd_party'][c_received].add((domain, ))
                        else:
                            to_display_received['not_sent'][c_received].add((domain, ))
                        continue

                    for url_node in ct.root_hartree.cookies_sent[c_received]:
                        if is_3rd_party:
                            to_display_received['3rd_party'][c_received].add((url_node.hostname, url_node.hostnode_uuid))
                        else:
                            to_display_received['sent'][c_received].add((url_node.hostname, url_node.hostnode_uuid))
                to_append['cookies_received'] = to_display_received

            urls.append(to_append)
        return hostnode, urls
