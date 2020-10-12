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

import dns.resolver
import dns.rdatatype
from defang import refang  # type: ignore
from har2tree import CrawledTree, Har2TreeError, HarFile, HostNode, URLNode
from redis import Redis
from scrapysplashwrapper import crawl
from werkzeug.useragents import UserAgent

from .exceptions import NoValidHarFile, MissingUUID
from .helpers import (get_homedir, get_socket_path, load_cookies, get_config,
                      safe_create_dir, get_email_template, load_pickle_tree,
                      remove_pickle_tree, get_resources_hashes)
from .modules import VirusTotal, SaneJavaScript, PhishingInitiative
from .context import Context
from .indexing import Indexing


class Lookyloo():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.indexing = Indexing()
        self.is_public_instance = get_config('generic', 'public_instance')

        self.redis: Redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)
        self.scrape_dir: Path = get_homedir() / 'scraped'
        if os.environ.get('SPLASH_URL_DOCKER'):
            # In order to have a working default for the docker image, it is easier to use an environment variable
            self.splash_url: str = os.environ['SPLASH_URL_DOCKER']
        else:
            self.splash_url = get_config('generic', 'splash_url')
        self.only_global_lookups: bool = get_config('generic', 'only_global_lookups')

        safe_create_dir(self.scrape_dir)

        # Initialize 3rd party components
        self.pi = PhishingInitiative(get_config('modules', 'PhishingInitiative'))
        if not self.pi.available:
            self.logger.warning('Unable to setup the PhishingInitiative module')

        self.vt = VirusTotal(get_config('modules', 'VirusTotal'))
        if not self.vt.available:
            self.logger.warning('Unable to setup the VirusTotal module')

        self.sanejs = SaneJavaScript(get_config('modules', 'SaneJS'))
        if not self.sanejs.available:
            self.logger.warning('Unable to setup the SaneJS module')

        if hasattr(self, 'sanejs') and self.sanejs.available:
            self.context = Context(self.sanejs)
        else:
            self.context = Context()

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
            if not parsed_ua.platform or not parsed_ua.browser:
                continue
            if parsed_ua.platform not in to_store:
                to_store[parsed_ua.platform] = {}
            if f'{parsed_ua.browser} {parsed_ua.version}' not in to_store[parsed_ua.platform]:
                to_store[parsed_ua.platform][f'{parsed_ua.browser} {parsed_ua.version}'] = []
            to_store[parsed_ua.platform][f'{parsed_ua.browser} {parsed_ua.version}'].append(parsed_ua.string)
            to_store['by_frequency'].append({'os': parsed_ua.platform,
                                             'browser': f'{parsed_ua.browser} {parsed_ua.version}',
                                             'useragent': parsed_ua.string})
        with self_generated_ua_file.open('w') as f:
            json.dump(to_store, f, indent=2)

    def cache_tree(self, capture_uuid: str) -> None:
        '''Generate the pickle, add capture in the indexes'''
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')

        with open((capture_dir / 'uuid'), 'r') as f:
            uuid = f.read()
        har_files = sorted(capture_dir.glob('*.har'))
        # NOTE: We only index the public captures
        index = True
        try:
            ct = CrawledTree(har_files, uuid)
            self.resolve_dns(ct)
            if self.is_public_instance:
                cache = self.capture_cache(capture_uuid)
                if cache.get('no_index') is not None:
                    index = False
            if index:
                self.indexing.index_cookies_capture(ct)
                self.indexing.index_body_hashes_capture(ct)
        except Har2TreeError as e:
            raise NoValidHarFile(e.message)

        with (capture_dir / 'tree.pickle').open('wb') as _p:
            pickle.dump(ct, _p)

    def _build_cname_chain(self, known_cnames: Dict[str, Optional[str]], hostname) -> List[str]:
        cnames: List[str] = []
        to_search = hostname
        while True:
            if known_cnames.get(to_search) is None:
                break
            # At this point, known_cnames[to_search] must exist and be a str
            cnames.append(known_cnames[to_search])  # type: ignore
            to_search = known_cnames[to_search]
        return cnames

    def resolve_dns(self, ct: CrawledTree):
        cnames_path = ct.root_hartree.har.path.parent / 'cnames.json'
        ips_path = ct.root_hartree.har.path.parent / 'ips.json'
        host_cnames: Dict[str, Optional[str]] = {}
        if cnames_path.exists():
            with cnames_path.open() as f:
                host_cnames = json.load(f)

        host_ips: Dict[str, List[str]] = {}
        if ips_path.exists():
            with ips_path.open() as f:
                host_ips = json.load(f)

        for node in ct.root_hartree.hostname_tree.traverse():
            if node.name not in host_cnames or node.name not in host_ips:
                # Resolve and cache
                try:
                    response = dns.resolver.resolve(node.name, search=True)
                    for answer in response.response.answer:
                        if answer.rdtype == dns.rdatatype.RdataType.CNAME:
                            host_cnames[str(answer.name).rstrip('.')] = str(answer[0].target).rstrip('.')
                        else:
                            host_cnames[str(answer.name).rstrip('.')] = None

                        if answer.rdtype in [dns.rdatatype.RdataType.A, dns.rdatatype.RdataType.AAAA]:
                            host_ips[str(answer.name).rstrip('.')] = list(set(str(b) for b in answer))
                except Exception:
                    host_cnames[node.name] = None
                    host_ips[node.name] = []
            cnames = self._build_cname_chain(host_cnames, node.name)
            if cnames:
                node.add_feature('cname', cnames)
                if cnames[-1] in host_ips:
                    node.add_feature('resolved_ips', host_ips[cnames[-1]])
            elif node.name in host_ips:
                node.add_feature('resolved_ips', host_ips[node.name])

        with cnames_path.open('w') as f:
            json.dump(host_cnames, f)
        with ips_path.open('w') as f:
            json.dump(host_ips, f)
        return ct

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

    def add_context(self, capture_uuid: str, urlnode_uuid: str, ressource_hash: str, legitimate: bool, malicious: bool, details: Dict[str, Dict[str, str]]):
        if malicious:
            self.context.add_malicious(ressource_hash, details['malicious'])
        if legitimate:
            self.context.add_legitimate(ressource_hash, details['legitimate'])

    def add_to_legitimate(self, capture_uuid: str, hostnode_uuid: Optional[str]=None, urlnode_uuid: Optional[str]=None):
        ct = self.get_crawled_tree(capture_uuid)
        self.context.mark_as_legitimate(ct, hostnode_uuid, urlnode_uuid)

    def load_tree(self, capture_uuid: str) -> Tuple[str, str, str, str, Dict[str, str]]:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        meta = {}
        if (capture_dir / 'meta').exists():
            with open((capture_dir / 'meta'), 'r') as f:
                meta = json.load(f)
        ct = self.get_crawled_tree(capture_uuid)
        ct = self.context.contextualize_tree(ct)
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
            self.redis.hmset(str(capture_dir), error_cache)  # type: ignore
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

        self.redis.hmset(str(capture_dir), cache)  # type: ignore
        self.redis.hset('lookup_dirs', uuid, str(capture_dir))

    def hide_capture(self, capture_uuid: str) -> None:
        """Add the capture in the hidden pool (not shown on the front page)
        NOTE: it won't remove the correlations until they are rebuilt.
        """
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        self.redis.hset(str(capture_dir), 'no_index', 1)
        (capture_dir / 'no_index').touch()

    @property
    def capture_uuids(self):
        return self.redis.hkeys('lookup_dirs')

    def capture_cache(self, capture_uuid: str) -> Dict[str, Union[str, Path]]:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        if self.redis.hget(str(capture_dir), 'incomplete_redirects') == '1':
            # try to rebuild the cache
            self._set_capture_cache(capture_dir, force=True)
        cached: Dict[str, Union[str, Path]] = self.redis.hgetall(str(capture_dir))  # type: ignore
        if all(key in cached.keys() for key in ['uuid', 'title', 'timestamp', 'url', 'redirects', 'capture_dir']):
            cached['redirects'] = json.loads(cached['redirects'])  # type: ignore
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
        capture_dir: str = self.redis.hget('lookup_dirs', capture_uuid)  # type: ignore
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
        to_scrape: Dict[str, Union[str, int, float]] = self.redis.hgetall(uuid)  # type: ignore
        self.redis.delete(uuid)
        to_scrape['perma_uuid'] = uuid
        if self.scrape(**to_scrape):  # type: ignore
            self.logger.info(f'Processed {to_scrape["url"]}')
            return True
        return False

    def send_mail(self, capture_uuid: str, email: str='', comment: str='') -> None:
        if not get_config('generic', 'enable_mail_notification'):
            return

        redirects = ''
        initial_url = ''
        cache = self.capture_cache(capture_uuid)
        if cache:
            initial_url = cache['url']  # type: ignore
            if 'redirects' in cache and cache['redirects']:
                redirects = "Redirects:\n"
                redirects += '\n'.join(cache['redirects'])  # type: ignore
            else:
                redirects = "No redirects."

        email_config = get_config('generic', 'email')
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
            self.logger.warning(msg.as_string())

    def _ensure_meta(self, capture_dir: Path, tree: CrawledTree) -> None:
        metafile = capture_dir / 'meta'
        if metafile.exists():
            return
        ua = UserAgent(tree.root_hartree.user_agent)
        to_dump = {}
        if ua.platform:
            to_dump['os'] = ua.platform
        if ua.browser:
            if ua.version:
                to_dump['browser'] = f'{ua.browser} {ua.version}'
            else:
                to_dump['browser'] = ua.browser
        if ua.language:
            to_dump['language'] = ua.language

        if not to_dump:
            # UA not recognized
            self.logger.info(f'Unable to recognize the User agent: {ua}')
        to_dump['user_agent'] = ua.string
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

    def scrape(self, url: str, cookies_pseudofile: Optional[Union[BufferedIOBase, str]]=None,
               depth: int=1, listing: bool=True, user_agent: Optional[str]=None,
               referer: str='', perma_uuid: Optional[str]=None, os: Optional[str]=None,
               browser: Optional[str]=None) -> Union[bool, str]:
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
            ua: str = get_config('generic', 'default_user_agent')
        else:
            ua = user_agent

        if int(depth) > int(get_config('generic', 'max_depth')):
            self.logger.warning(f'Not allowed to scrape on a depth higher than {get_config("generic", "max_depth")}: {depth}')
            depth = int(get_config('generic', 'max_depth'))
        items = crawl(self.splash_url, url, cookies=cookies, depth=depth, user_agent=ua,
                      referer=referer, log_enabled=True, log_level=get_config('generic', 'splash_loglevel'))
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

    def get_body_hash_investigator(self, body_hash: str) -> Tuple[List[Tuple[str, str]], List[Tuple[str, float]]]:
        captures: List[Tuple[str, str]] = []
        total_captures, details = self.indexing.get_body_hash_captures(body_hash, limit=-1)
        for capture_uuid, url_uuid, url_hostname, _ in details:
            cache = self.capture_cache(capture_uuid)
            if cache:
                captures.append((capture_uuid, cache['title']))  # type: ignore
        domains = self.indexing.get_body_hash_domains(body_hash)
        return captures, domains

    def get_cookie_name_investigator(self, cookie_name: str):
        captures = []
        for capture_uuid, url_uuid in self.indexing.get_cookies_names_captures(cookie_name):
            cache = self.capture_cache(capture_uuid)
            if cache:
                captures.append((capture_uuid, cache['title']))
        domains = [(domain, freq, self.indexing.cookies_names_domains_values(cookie_name, domain))
                   for domain, freq in self.indexing.get_cookie_domains(cookie_name)]
        return captures, domains

    def hash_lookup(self, blob_hash: str, url: str, capture_uuid: str) -> Tuple[int, Dict[str, List[Tuple[str, str, str, str, str]]]]:
        captures_list: Dict[str, List[Tuple[str, str, str, str, str]]] = {'same_url': [], 'different_url': []}
        total_captures, details = self.indexing.get_body_hash_captures(blob_hash, url, filter_capture_uuid=capture_uuid)
        for h_capture_uuid, url_uuid, url_hostname, same_url in details:
            cache = self.capture_cache(h_capture_uuid)
            if cache:
                if same_url:
                    captures_list['same_url'].append((h_capture_uuid, url_uuid, cache['title'], cache['timestamp'], url_hostname))  # type: ignore
                else:
                    captures_list['different_url'].append((h_capture_uuid, url_uuid, cache['title'], cache['timestamp'], url_hostname))  # type: ignore
        return total_captures, captures_list

    def _normalize_known_content(self, h: str, known_content: Dict[str, Any], url: URLNode):
        known: Optional[Union[str, List[Any]]] = None
        legitimate: Optional[Tuple[bool, Any]] = None
        if h not in known_content:
            return known, legitimate

        if known_content[h]['type'] in ['generic', 'sanejs']:
            known = known_content[h]['details']
        elif known_content[h]['type'] == 'legitimate_on_domain':
            legit = False
            if url.hostname in known_content[h]['details']:
                legit = True
            legitimate = (legit, known_content[h]['details'])
        elif known_content[h]['type'] == 'malicious':
            legitimate = (False, known_content[h]['details'])

        return known, legitimate

    def get_ressource(self, tree_uuid: str, urlnode_uuid: str, h: Optional[str]) -> Optional[Tuple[str, BytesIO]]:
        url = self.get_urlnode_from_tree(tree_uuid, urlnode_uuid)
        if url.empty_response:
            return None
        if not h or h == url.body_hash:
            # we want the body
            return url.filename if url.filename else 'file.bin', url.body

        # We want an embedded ressource
        if h not in url.resources_hashes:
            return None
        for mimetype, blobs in url.embedded_ressources.items():
            for ressource_h, blob in blobs:
                if ressource_h == h:
                    return 'embedded_ressource.bin', blob
        return None

    def get_hashes(self, tree_uuid: str, hostnode_uuid: Optional[str]=None, urlnode_uuid: Optional[str]=None) -> Set[str]:
        """Return hashes of resources.
        Only tree_uuid: All the hashes
        tree_uuid and hostnode_uuid: hashes of all the resources in that hostnode (including embedded ressources)
        tree_uuid, hostnode_uuid, and urlnode_uuid: hash of the URL node body, and embedded resources
        """
        container: Union[CrawledTree, HostNode, URLNode]
        if urlnode_uuid:
            container = self.get_urlnode_from_tree(tree_uuid, urlnode_uuid)
        elif hostnode_uuid:
            container = self.get_hostnode_from_tree(tree_uuid, hostnode_uuid)
        else:
            container = self.get_crawled_tree(tree_uuid)
        return get_resources_hashes(container)

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

        cnames_path = ct.root_hartree.har.path.parent / 'cnames.json'
        if cnames_path.exists():
            with cnames_path.open() as f:
                host_cnames = json.load(f)
            cnames = self._build_cname_chain(host_cnames, hostnode.name)
            if cnames:
                hostnode.add_feature('cname', cnames)

        known_content = self.context.find_known_content(hostnode)

        urls: List[Dict[str, Any]] = []
        for url in hostnode.urls:
            # For the popup, we need:
            # * https vs http
            # * everything after the domain
            # * the full URL
            to_append: Dict[str, Any] = {
                'encrypted': url.name.startswith('https'),
                'url_path': url.name.split('/', 3)[-1],
                'url_object': url,
            }

            if not url.empty_response:
                # Index lookup
                # %%% Full body %%%
                freq = self.indexing.body_hash_fequency(url.body_hash)
                to_append['body_hash_details'] = freq
                if freq and 'hash_freq' in freq and freq['hash_freq'] and freq['hash_freq'] > 1:
                    to_append['body_hash_details']['other_captures'] = self.hash_lookup(url.body_hash, url.name, capture_uuid)

                # %%% Embedded ressources %%%
                if hasattr(url, 'embedded_ressources') and url.embedded_ressources:
                    to_append['embedded_ressources'] = {}
                    for mimetype, blobs in url.embedded_ressources.items():
                        for h, blob in blobs:
                            if h in to_append['embedded_ressources']:
                                # Skip duplicates
                                continue
                            freq_embedded = self.indexing.body_hash_fequency(h)
                            to_append['embedded_ressources'][h] = freq_embedded
                            to_append['embedded_ressources'][h]['body_size'] = blob.getbuffer().nbytes
                            to_append['embedded_ressources'][h]['type'] = mimetype
                            if freq_embedded['hash_freq'] > 1:
                                to_append['embedded_ressources'][h]['other_captures'] = self.hash_lookup(h, url.name, capture_uuid)
                    for h in to_append['embedded_ressources'].keys():
                        known, legitimate = self._normalize_known_content(h, known_content, url)
                        if known:
                            to_append['embedded_ressources'][h]['known_content'] = known
                        elif legitimate:
                            to_append['embedded_ressources'][h]['legitimacy'] = legitimate

                known, legitimate = self._normalize_known_content(url.body_hash, known_content, url)
                if known:
                    to_append['known_content'] = known
                elif legitimate:
                    to_append['legitimacy'] = legitimate

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
