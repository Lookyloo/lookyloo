#!/usr/bin/env python3

import base64
import json
import logging
import operator
import smtplib
from collections import defaultdict
from datetime import date, datetime
from email.message import EmailMessage
from io import BytesIO
from pathlib import Path
from typing import (Any, Dict, Iterable, List, MutableMapping, Optional, Set,
                    Tuple, Union)
from uuid import uuid4
from zipfile import ZipFile

from defang import defang  # type: ignore
from har2tree import CrawledTree, HostNode, URLNode
from PIL import Image  # type: ignore
from pymisp import MISPAttribute, MISPEvent, MISPObject
from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection

from .capturecache import CaptureCache, CapturesIndex
from .context import Context
from .default import LookylooException, get_homedir, get_config, get_socket_path
from .exceptions import (MissingCaptureDirectory,
                         MissingUUID, TreeNeedsRebuild, NoValidHarFile)
from .helpers import (CaptureStatus, get_captures_dir, get_email_template,
                      get_resources_hashes, get_taxonomies,
                      uniq_domains, ParsedUserAgent)
from .indexing import Indexing
from .modules import (MISP, PhishingInitiative, UniversalWhois,
                      UrlScan, VirusTotal, Phishtank, Hashlookup)


class Lookyloo():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.indexing = Indexing()
        self.is_public_instance = get_config('generic', 'public_instance')
        self.public_domain = get_config('generic', 'public_domain')
        self.taxonomies = get_taxonomies()

        self.redis_pool: ConnectionPool = ConnectionPool(connection_class=UnixDomainSocketConnection,
                                                         path=get_socket_path('cache'), decode_responses=True)
        self.capture_dir: Path = get_captures_dir()

        self._priority = get_config('generic', 'priority')

        # Initialize 3rd party components
        self.pi = PhishingInitiative(get_config('modules', 'PhishingInitiative'))
        if not self.pi.available:
            self.logger.warning('Unable to setup the PhishingInitiative module')

        self.vt = VirusTotal(get_config('modules', 'VirusTotal'))
        if not self.vt.available:
            self.logger.warning('Unable to setup the VirusTotal module')

        self.misp = MISP(get_config('modules', 'MISP'))
        if not self.misp.available:
            self.logger.warning('Unable to setup the MISP module')

        self.uwhois = UniversalWhois(get_config('modules', 'UniversalWhois'))
        if not self.uwhois.available:
            self.logger.warning('Unable to setup the UniversalWhois module')

        self.urlscan = UrlScan(get_config('modules', 'UrlScan'))
        if not self.urlscan.available:
            self.logger.warning('Unable to setup the UrlScan module')

        self.phishtank = Phishtank(get_config('modules', 'Phishtank'))
        if not self.phishtank.available:
            self.logger.warning('Unable to setup the Phishtank module')

        self.hashlookup = Hashlookup(get_config('modules', 'Hashlookup'))
        if not self.hashlookup.available:
            self.logger.warning('Unable to setup the Hashlookup module')

        self.logger.info('Initializing context...')
        self.context = Context()
        self.logger.info('Context initialized.')
        self.logger.info('Initializing index...')
        self._captures_index = CapturesIndex(self.redis, self.context)
        self.logger.info('Index initialized.')

    @property
    def redis(self):
        return Redis(connection_pool=self.redis_pool)

    def add_context(self, capture_uuid: str, /, urlnode_uuid: str, *, ressource_hash: str,
                    legitimate: bool, malicious: bool, details: Dict[str, Dict[str, str]]):
        '''Adds context information to a capture or a URL node'''
        if malicious:
            self.context.add_malicious(ressource_hash, details['malicious'])
        if legitimate:
            self.context.add_legitimate(ressource_hash, details['legitimate'])

    def add_to_legitimate(self, capture_uuid: str, /, hostnode_uuid: Optional[str]=None, urlnode_uuid: Optional[str]=None):
        '''Mark a full capture as legitimate.
        Iterates over all the nodes and mark them all as legitimate too.'''
        ct = self.get_crawled_tree(capture_uuid)
        self.context.mark_as_legitimate(ct, hostnode_uuid, urlnode_uuid)

    def remove_pickle(self, capture_uuid: str, /) -> None:
        '''Remove the pickle from a specific capture.'''
        self._captures_index.remove_pickle(capture_uuid)

    def rebuild_cache(self) -> None:
        '''Flush and rebuild the redis cache. Doesn't remove the pickles.
        The cached captures will be rebuild when loading the index.'''
        self.redis.flushdb()

    def rebuild_all(self) -> None:
        '''Flush and rebuild the redis cache, and delete all the pickles.
        The captures will be rebuilt by the background indexer'''
        self._captures_index.rebuild_all()

    def get_urlnode_from_tree(self, capture_uuid: str, /, node_uuid: str) -> URLNode:
        '''Get a URL node from a tree, by UUID'''
        ct = self.get_crawled_tree(capture_uuid)
        return ct.root_hartree.get_url_node_by_uuid(node_uuid)

    def get_hostnode_from_tree(self, capture_uuid: str, /, node_uuid: str) -> HostNode:
        '''Get a host node from a tree, by UUID'''
        ct = self.get_crawled_tree(capture_uuid)
        return ct.root_hartree.get_host_node_by_uuid(node_uuid)

    def get_statistics(self, capture_uuid: str, /) -> Dict[str, Any]:
        '''Get the statistics of a capture.'''
        ct = self.get_crawled_tree(capture_uuid)
        return ct.root_hartree.stats

    def get_info(self, capture_uuid: str, /) -> Dict[str, Any]:
        '''Get basic information about the capture.'''
        ct = self.get_crawled_tree(capture_uuid)
        to_return = {'url': ct.root_url, 'title': ct.root_hartree.har.initial_title,
                     'capture_time': ct.start_time.isoformat(), 'user_agent': ct.user_agent,
                     'referer': ct.referer}
        return to_return

    def get_meta(self, capture_uuid: str, /) -> Dict[str, str]:
        '''Get the meta informations from a capture (mostly, details about the User Agent used.)'''
        metafile = self._captures_index[capture_uuid].capture_dir / 'meta'
        if metafile.exists():
            with metafile.open('r') as f:
                return json.load(f)

        meta = {}
        ct = self.get_crawled_tree(capture_uuid)
        ua = ParsedUserAgent(ct.root_hartree.user_agent)
        meta['user_agent'] = ua.string
        if ua.platform:
            meta['os'] = ua.platform
        if ua.browser:
            if ua.version:
                meta['browser'] = f'{ua.browser} {ua.version}'
            else:
                meta['browser'] = ua.browser

        if not meta:
            # UA not recognized
            self.logger.info(f'Unable to recognize the User agent: {ua}')
        with metafile.open('w') as f:
            json.dump(meta, f)
        return meta

    def categories_capture(self, capture_uuid: str, /) -> Dict[str, Any]:
        '''Get all the categories related to a capture, in MISP Taxonomies format'''
        categ_file = self._captures_index[capture_uuid].capture_dir / 'categories'
        # get existing categories if possible
        if categ_file.exists():
            with categ_file.open() as f:
                current_categories = [line.strip() for line in f.readlines()]
            return {e: self.taxonomies.revert_machinetag(e) for e in current_categories}
        return {}

    def categorize_capture(self, capture_uuid: str, /, category: str) -> None:
        '''Add a category (MISP Taxonomy tag) to a capture.'''
        if not get_config('generic', 'enable_categorization'):
            return
        # Make sure the category is mappable to a taxonomy.
        self.taxonomies.revert_machinetag(category)

        categ_file = self._captures_index[capture_uuid].capture_dir / 'categories'
        # get existing categories if possible
        if categ_file.exists():
            with categ_file.open() as f:
                current_categories = {line.strip() for line in f.readlines()}
        else:
            current_categories = set()
        current_categories.add(category)
        with categ_file.open('w') as f:
            f.writelines(f'{t}\n' for t in current_categories)

    def uncategorize_capture(self, capture_uuid: str, /, category: str) -> None:
        '''Remove a category (MISP Taxonomy tag) from a capture.'''
        if not get_config('generic', 'enable_categorization'):
            return
        categ_file = self._captures_index[capture_uuid].capture_dir / 'categories'
        # get existing categories if possible
        if categ_file.exists():
            with categ_file.open() as f:
                current_categories = {line.strip() for line in f.readlines()}
        else:
            current_categories = set()
        current_categories.remove(category)
        with categ_file.open('w') as f:
            f.writelines(f'{t}\n' for t in current_categories)

    def trigger_modules(self, capture_uuid: str, /, force: bool=False, auto_trigger: bool=False) -> Dict:
        '''Launch the 3rd party modules on a capture.
        It uses the cached result *if* the module was triggered the same day.
        The `force` flag re-triggers the module regardless of the cache.'''
        try:
            ct = self.get_crawled_tree(capture_uuid)
        except LookylooException:
            self.logger.warning(f'Unable to trigger the modules unless the tree ({capture_uuid}) is cached.')
            return {'error': f'UUID {capture_uuid} is either unknown or the tree is not ready yet.'}

        self.uwhois.capture_default_trigger(ct, force=force, auto_trigger=auto_trigger)
        self.hashlookup.capture_default_trigger(ct, auto_trigger=auto_trigger)

        to_return: Dict[str, Dict] = {'PhishingInitiative': {}, 'VirusTotal': {}, 'UrlScan': {}}
        capture_cache = self.capture_cache(capture_uuid)

        to_return['PhishingInitiative'] = self.pi.capture_default_trigger(ct, force=force, auto_trigger=auto_trigger)
        to_return['VirusTotal'] = self.vt.capture_default_trigger(ct, force=force, auto_trigger=auto_trigger)
        to_return['UrlScan'] = self.urlscan.capture_default_trigger(
            self.get_info(capture_uuid),
            visibility='unlisted' if (capture_cache and capture_cache.no_index) else 'public',
            force=force, auto_trigger=auto_trigger)
        to_return['Phishtank'] = self.phishtank.capture_default_trigger(ct, auto_trigger=auto_trigger)
        return to_return

    def get_modules_responses(self, capture_uuid: str, /) -> Optional[Dict[str, Any]]:
        '''Get the responses of the modules from the cached responses on the disk'''
        try:
            ct = self.get_crawled_tree(capture_uuid)
        except LookylooException:
            self.logger.warning(f'Unable to get the modules responses unless the tree ({capture_uuid}) is cached.')
            return None
        to_return: Dict[str, Any] = {}
        if self.vt.available:
            to_return['vt'] = {}
            if ct.redirects:
                for redirect in ct.redirects:
                    to_return['vt'][redirect] = self.vt.get_url_lookup(redirect)
            else:
                to_return['vt'][ct.root_hartree.har.root_url] = self.vt.get_url_lookup(ct.root_hartree.har.root_url)
        if self.pi.available:
            to_return['pi'] = {}
            if ct.redirects:
                for redirect in ct.redirects:
                    to_return['pi'][redirect] = self.pi.get_url_lookup(redirect)
            else:
                to_return['pi'][ct.root_hartree.har.root_url] = self.pi.get_url_lookup(ct.root_hartree.har.root_url)
        if self.phishtank.available:
            to_return['phishtank'] = {'urls': {}, 'ips_hits': {}}
            if ct.redirects:
                for redirect in ct.redirects:
                    to_return['phishtank']['urls'][redirect] = self.phishtank.get_url_lookup(redirect)
            else:
                to_return['phishtank']['urls'][ct.root_hartree.har.root_url] = self.phishtank.get_url_lookup(ct.root_hartree.har.root_url)
            ips_hits = self.phishtank.lookup_ips_capture(ct)
            if ips_hits:
                to_return['phishtank']['ips_hits'] = ips_hits
        if self.urlscan.available:
            info = self.get_info(capture_uuid)
            to_return['urlscan'] = {'submission': {}, 'result': {}}
            to_return['urlscan']['submission'] = self.urlscan.get_url_submission(info)
            if to_return['urlscan']['submission'] and 'uuid' in to_return['urlscan']['submission']:
                # The submission was done, try to get the results
                result = self.urlscan.url_result(info)
                if 'error' not in result:
                    to_return['urlscan']['result'] = result
        return to_return

    def hide_capture(self, capture_uuid: str, /) -> None:
        """Add the capture in the hidden pool (not shown on the front page)
        NOTE: it won't remove the correlations until they are rebuilt.
        """
        capture_dir = self._captures_index[capture_uuid].capture_dir
        self.redis.hset(str(capture_dir), 'no_index', 1)
        (capture_dir / 'no_index').touch()
        self._captures_index.reload_cache(capture_uuid)

    def update_tree_cache_info(self, process_id: int, classname: str) -> None:
        self.redis.hset('tree_cache', f'{process_id}|{classname}', str(self._captures_index.lru_cache_status()))

    def sorted_capture_cache(self, capture_uuids: Optional[Iterable[str]]=None) -> List[CaptureCache]:
        '''Get all the captures in the cache, sorted by timestamp (new -> old).'''
        if capture_uuids is None:
            # Sort all recent captures
            capture_uuids = self.redis.hkeys('lookup_dirs')
        if not capture_uuids:
            # No captures at all on the instance
            return []

        all_cache: List[CaptureCache] = [self._captures_index[uuid] for uuid in capture_uuids if self.capture_cache(uuid)]
        all_cache.sort(key=operator.attrgetter('timestamp'), reverse=True)
        return all_cache

    def get_capture_status(self, capture_uuid: str, /) -> CaptureStatus:
        '''Returns the status (queued, ongoing, done, or UUID unknown)'''
        if self.redis.zrank('to_capture', capture_uuid) is not None:
            return CaptureStatus.QUEUED
        elif self.redis.hexists('lookup_dirs', capture_uuid):
            return CaptureStatus.DONE
        elif self.redis.sismember('ongoing', capture_uuid):
            return CaptureStatus.ONGOING
        return CaptureStatus.UNKNOWN

    def try_error_status(self, capture_uuid: str, /) -> Optional[str]:
        '''If it is not possible to do the capture, we store the error for a short amount of time'''
        return self.redis.get(f'error_{capture_uuid}')

    def capture_cache(self, capture_uuid: str, /) -> Optional[CaptureCache]:
        """Get the cache from redis."""
        try:
            return self._captures_index[capture_uuid]
        except MissingCaptureDirectory as e:
            # The UUID is in the captures but the directory is not on the disk.
            self.logger.warning(e)
            return None
        except MissingUUID:
            if self.get_capture_status(capture_uuid) not in [CaptureStatus.QUEUED, CaptureStatus.ONGOING]:
                self.logger.warning(f'Unable to find {capture_uuid} (not in the cache and/or missing capture directory).')
            return None
        except LookylooException as e:
            self.logger.warning(e)
            return None
        except Exception as e:
            self.logger.exception(e)
            return None

    def get_crawled_tree(self, capture_uuid: str, /) -> CrawledTree:
        '''Get the generated tree in ETE Toolkit format.
        Loads the pickle if it exists, creates it otherwise.'''
        try:
            return self._captures_index[capture_uuid].tree
        except TreeNeedsRebuild:
            self._captures_index.reload_cache(capture_uuid)
            return self._captures_index[capture_uuid].tree

    def enqueue_capture(self, query: MutableMapping[str, Any], source: str, user: str, authenticated: bool) -> str:
        '''Enqueue a query in the capture queue (used by the UI and the API for asynchronous processing)'''

        def get_priority(source: str, user: str, authenticated: bool) -> int:
            src_prio: int = self._priority['sources'][source] if source in self._priority['sources'] else -1
            if not authenticated:
                usr_prio = self._priority['users']['_default_anon']
                # reduce priority for anonymous users making lots of captures
                queue_size = self.redis.zscore('queues', f'{source}|{authenticated}|{user}')
                if queue_size is None:
                    queue_size = 0
                usr_prio -= int(queue_size / 10)
            else:
                usr_prio = self._priority['users'][user] if self._priority['users'].get(user) else self._priority['users']['_default_auth']
            return src_prio + usr_prio

        priority = get_priority(source, user, authenticated)
        perma_uuid = str(uuid4())
        p = self.redis.pipeline()
        for key, value in query.items():
            if isinstance(value, bool):
                query[key] = 1 if value else 0
            if isinstance(value, (list, dict)):
                query[key] = json.dumps(value)
        if priority < -10:
            # Someone is probably abusing the system with useless URLs, remove them from the index
            query['listing'] = 0
        p.hmset(perma_uuid, query)
        p.zadd('to_capture', {perma_uuid: priority})
        p.zincrby('queues', 1, f'{source}|{authenticated}|{user}')
        p.set(f'{perma_uuid}_mgmt', f'{source}|{authenticated}|{user}')
        p.execute()
        return perma_uuid

    def send_mail(self, capture_uuid: str, /, email: str='', comment: str='') -> None:
        '''Send an email notification regarding a specific capture'''
        if not get_config('generic', 'enable_mail_notification'):
            return

        redirects = ''
        initial_url = ''
        cache = self.capture_cache(capture_uuid)
        if cache:
            initial_url = defang(cache.url, colon=True, all_dots=True)
            if cache.redirects:
                redirects = "Redirects:\n"
                redirects += defang('\n'.join(cache.redirects), colon=True, all_dots=True)
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
            domain=self.public_domain,
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

    def _get_raw(self, capture_uuid: str, /, extension: str='*', all_files: bool=True) -> BytesIO:
        '''Get file(s) from the capture directory'''
        try:
            capture_dir = self._captures_index[capture_uuid].capture_dir
        except MissingUUID:
            return BytesIO(f'Capture {capture_uuid} not unavailable, try again later.'.encode())
        except MissingCaptureDirectory:
            return BytesIO(f'No capture {capture_uuid} on the system (directory missing).'.encode())
        all_paths = sorted(list(capture_dir.glob(f'*.{extension}')))
        if not all_files:
            # Only get the first one in the list
            with open(all_paths[0], 'rb') as f:
                return BytesIO(f.read())
        to_return = BytesIO()
        # Add uuid file to the export, allows to keep the same UUID across platforms.
        all_paths.append(capture_dir / 'uuid')
        with ZipFile(to_return, 'w') as myzip:
            for path in all_paths:
                if path.name.endswith('pickle'):
                    continue
                myzip.write(path, arcname=f'{capture_dir.name}/{path.name}')
        to_return.seek(0)
        return to_return

    def get_html(self, capture_uuid: str, /, all_html: bool=False) -> BytesIO:
        '''Get rendered HTML'''
        return self._get_raw(capture_uuid, 'html', all_html)

    def get_cookies(self, capture_uuid: str, /, all_cookies: bool=False) -> BytesIO:
        '''Get the cookie(s)'''
        return self._get_raw(capture_uuid, 'cookies.json', all_cookies)

    def get_screenshot(self, capture_uuid: str, /) -> BytesIO:
        '''Get the screenshot(s) of the rendered page'''
        return self._get_raw(capture_uuid, 'png', all_files=False)

    def get_screenshot_thumbnail(self, capture_uuid: str, /, for_datauri: bool=False, width: int=64) -> Union[str, BytesIO]:
        '''Get the thumbnail of the rendered page. Always crop to a square.'''
        to_return = BytesIO()
        size = width, width
        try:
            s = self.get_screenshot(capture_uuid)
            orig_screenshot = Image.open(s)
            to_thumbnail = orig_screenshot.crop((0, 0, orig_screenshot.width, orig_screenshot.width))
        except Image.DecompressionBombError as e:
            # The image is most probably too big: https://pillow.readthedocs.io/en/stable/reference/Image.html
            self.logger.warning(f'Unable to generate the screenshot thumbnail of {capture_uuid}: image too big ({e}).')
            error_img: Path = get_homedir() / 'website' / 'web' / 'static' / 'error_screenshot.png'
            to_thumbnail = Image.open(error_img)

        to_thumbnail.thumbnail(size)
        to_thumbnail.save(to_return, 'png')

        to_return.seek(0)
        if for_datauri:
            return base64.b64encode(to_return.getvalue()).decode()
        else:
            return to_return

    def get_capture(self, capture_uuid: str, /) -> BytesIO:
        '''Get all the files related to this capture.'''
        return self._get_raw(capture_uuid)

    def get_urls_rendered_page(self, capture_uuid: str, /):
        ct = self.get_crawled_tree(capture_uuid)
        return sorted(set(ct.root_hartree.rendered_node.urls_in_rendered_page)
                      - set(ct.root_hartree.all_url_requests.keys()))

    def get_body_hash_investigator(self, body_hash: str, /) -> Tuple[List[Tuple[str, str]], List[Tuple[str, float]]]:
        '''Returns all the captures related to a hash (sha512), used in the web interface.'''
        total_captures, details = self.indexing.get_body_hash_captures(body_hash, limit=-1)
        cached_captures = self.sorted_capture_cache([d[0] for d in details])
        captures = [(cache.uuid, cache.title) for cache in cached_captures]
        domains = self.indexing.get_body_hash_domains(body_hash)
        return captures, domains

    def get_body_hash_full(self, body_hash: str, /) -> Tuple[Dict[str, List[Dict[str, str]]], BytesIO]:
        '''Returns a lot of information about the hash (sha512) and the hits in the instance.
        Also contains the data (base64 encoded)'''
        details = self.indexing.get_body_hash_urls(body_hash)
        body_content = BytesIO()
        # get the body from the first entry in the details list
        for _, entries in details.items():
            ct = self.get_crawled_tree(entries[0]['capture'])
            urlnode = ct.root_hartree.get_url_node_by_uuid(entries[0]['urlnode'])
            if urlnode.body_hash == body_hash:
                # the hash we're looking for is the whole file
                body_content = urlnode.body
            else:
                # The hash is an embedded resource
                for _, blobs in urlnode.body_hash.embedded_ressources.items():
                    for h, b in blobs:
                        if h == body_hash:
                            body_content = b
                            break
            break
        return details, body_content

    def get_latest_url_capture(self, url: str, /) -> Optional[CaptureCache]:
        '''Get the most recent capture with this URL'''
        captures = self.sorted_capture_cache(self.indexing.get_captures_url(url))
        if captures:
            return captures[0]
        return None

    def get_url_occurrences(self, url: str, /, limit: int=20) -> List[Dict]:
        '''Get the most recent captures and URL nodes where the URL has been seen.'''
        captures = self.sorted_capture_cache(self.indexing.get_captures_url(url))

        to_return: List[Dict] = []
        for capture in captures[:limit]:
            ct = self.get_crawled_tree(capture.uuid)
            to_append: Dict[str, Union[str, Dict]] = {'capture_uuid': capture.uuid,
                                                      'start_timestamp': capture.timestamp.isoformat(),
                                                      'title': capture.title}
            urlnodes: Dict[str, Dict[str, str]] = {}
            for urlnode in ct.root_hartree.url_tree.search_nodes(name=url):
                urlnodes[urlnode.uuid] = {'start_time': urlnode.start_time.isoformat(),
                                          'hostnode_uuid': urlnode.hostnode_uuid}
                if hasattr(urlnode, 'body_hash'):
                    urlnodes[urlnode.uuid]['hash'] = urlnode.body_hash
            to_append['urlnodes'] = urlnodes
            to_return.append(to_append)
        return to_return

    def get_hostname_occurrences(self, hostname: str, /, with_urls_occurrences: bool=False, limit: int=20) -> List[Dict]:
        '''Get the most recent captures and URL nodes where the hostname has been seen.'''
        captures = self.sorted_capture_cache(self.indexing.get_captures_hostname(hostname))

        to_return: List[Dict] = []
        for capture in captures[:limit]:
            ct = self.get_crawled_tree(capture.uuid)
            to_append: Dict[str, Union[str, List, Dict]] = {'capture_uuid': capture.uuid,
                                                            'start_timestamp': capture.timestamp.isoformat(),
                                                            'title': capture.title}
            hostnodes: List[str] = []
            if with_urls_occurrences:
                urlnodes: Dict[str, Dict[str, str]] = {}
            for hostnode in ct.root_hartree.hostname_tree.search_nodes(name=hostname):
                hostnodes.append(hostnode.uuid)
                if with_urls_occurrences:
                    for urlnode in hostnode.urls:
                        urlnodes[urlnode.uuid] = {'start_time': urlnode.start_time.isoformat(),
                                                  'url': urlnode.name,
                                                  'hostnode_uuid': urlnode.hostnode_uuid}
                        if hasattr(urlnode, 'body_hash'):
                            urlnodes[urlnode.uuid]['hash'] = urlnode.body_hash
                to_append['hostnodes'] = hostnodes
                if with_urls_occurrences:
                    to_append['urlnodes'] = urlnodes
                to_return.append(to_append)
        return to_return

    def get_cookie_name_investigator(self, cookie_name: str, /) -> Tuple[List[Tuple[str, str]], List[Tuple[str, float, List[Tuple[str, float]]]]]:
        '''Returns all the captures related to a cookie name entry, used in the web interface.'''
        cached_captures = self.sorted_capture_cache([entry[0] for entry in self.indexing.get_cookies_names_captures(cookie_name)])
        captures = [(cache.uuid, cache.title) for cache in cached_captures]
        domains = [(domain, freq, self.indexing.cookies_names_domains_values(cookie_name, domain))
                   for domain, freq in self.indexing.get_cookie_domains(cookie_name)]
        return captures, domains

    def hash_lookup(self, blob_hash: str, url: str, capture_uuid: str) -> Tuple[int, Dict[str, List[Tuple[str, str, str, str, str]]]]:
        '''Search all the captures a specific hash was seen.
        If a URL is given, it splits the results if the hash is seen on the same URL or an other one.
        Capture UUID avoids duplicates on the same capture'''
        captures_list: Dict[str, List[Tuple[str, str, str, str, str]]] = {'same_url': [], 'different_url': []}
        total_captures, details = self.indexing.get_body_hash_captures(blob_hash, url, filter_capture_uuid=capture_uuid)
        for h_capture_uuid, url_uuid, url_hostname, same_url in details:
            cache = self.capture_cache(h_capture_uuid)
            if cache:
                if same_url:
                    captures_list['same_url'].append((h_capture_uuid, url_uuid, cache.title, cache.timestamp.isoformat(), url_hostname))
                else:
                    captures_list['different_url'].append((h_capture_uuid, url_uuid, cache.title, cache.timestamp.isoformat(), url_hostname))
        return total_captures, captures_list

    def get_ressource(self, tree_uuid: str, /, urlnode_uuid: str, h: Optional[str]) -> Optional[Tuple[str, BytesIO, str]]:
        '''Get a specific resource from a URL node. If a hash s also given, we want an embeded resource'''
        try:
            url = self.get_urlnode_from_tree(tree_uuid, urlnode_uuid)
        except IndexError:
            # unable to find the uuid, the cache is probably in a weird state.
            return None
        except NoValidHarFile as e:
            # something went poorly when rebuilding the tree (probably a recursive error)
            self.logger.warning(e)
            return None
        if url.empty_response:
            return None
        if not h or h == url.body_hash:
            # we want the body
            return url.filename if url.filename else 'file.bin', BytesIO(url.body.getvalue()), url.mimetype

        # We want an embedded ressource
        if h not in url.resources_hashes:
            return None
        for mimetype, blobs in url.embedded_ressources.items():
            for ressource_h, blob in blobs:
                if ressource_h == h:
                    return 'embedded_ressource.bin', BytesIO(blob.getvalue()), mimetype
        return None

    def __misp_add_vt_to_URLObject(self, obj: MISPObject) -> Optional[MISPObject]:
        urls = obj.get_attributes_by_relation('url')
        url = urls[0]
        self.vt.url_lookup(url.value)
        report = self.vt.get_url_lookup(url.value)
        if not report:
            return None
        vt_obj = MISPObject('virustotal-report', standalone=False)
        vt_obj.add_attribute('first-submission', value=datetime.fromtimestamp(report['attributes']['first_submission_date']), disable_correlation=True)
        vt_obj.add_attribute('last-submission', value=datetime.fromtimestamp(report['attributes']['last_submission_date']), disable_correlation=True)
        vt_obj.add_attribute('permalink', value=f"https://www.virustotal.com/gui/url/{report['id']}/detection", disable_correlation=True)
        obj.add_reference(vt_obj, 'analysed-with')
        return vt_obj

    def __misp_add_urlscan_to_event(self, capture_uuid: str, visibility: str) -> Optional[MISPAttribute]:
        response = self.urlscan.url_submit(self.get_info(capture_uuid), visibility)
        if 'result' in response:
            attribute = MISPAttribute()
            attribute.value = response['result']
            attribute.type = 'link'
            return attribute
        return None

    def misp_export(self, capture_uuid: str, /, with_parent: bool=False) -> Union[List[MISPEvent], Dict[str, str]]:
        '''Export a capture in MISP format. You can POST the return of this method
        directly to a MISP instance and it will create an event.'''
        cache = self.capture_cache(capture_uuid)
        if not cache:
            return {'error': 'UUID missing in cache, try again later.'}

        event = self.misp.export(cache, self.is_public_instance)
        screenshot: MISPAttribute = event.add_attribute('attachment', 'screenshot_landing_page.png',
                                                        data=self.get_screenshot(cache.uuid),
                                                        disable_correlation=True)  # type: ignore
        # If the last object attached to tht event is a file, it is the rendered page
        if event.objects and event.objects[-1].name == 'file':
            event.objects[-1].add_reference(screenshot, 'rendered-as', 'Screenshot of the page')

        if self.vt.available:
            for e_obj in event.objects:
                if e_obj.name != 'url':
                    continue
                vt_obj = self.__misp_add_vt_to_URLObject(e_obj)
                if vt_obj:
                    event.add_object(vt_obj)

        if self.phishtank.available:
            for e_obj in event.objects:
                if e_obj.name != 'url':
                    continue
                urls = e_obj.get_attributes_by_relation('url')
                if not urls:
                    continue
                pt_entry = self.phishtank.get_url_lookup(urls[0].value)
                if not pt_entry or not pt_entry.get('phish_detail_url'):
                    continue
                pt_attribute: MISPAttribute = event.add_attribute('link', value=pt_entry['phish_detail_url'], comment='Phishtank permalink')  # type: ignore
                e_obj.add_reference(pt_attribute, 'known-as', 'Permalink on Phishtank')

        if self.urlscan.available:
            urlscan_attribute = self.__misp_add_urlscan_to_event(
                capture_uuid,
                visibility='unlisted' if (cache and cache.no_index) else 'public')
            if urlscan_attribute:
                event.add_attribute(**urlscan_attribute)

        if with_parent and cache.parent:
            parent = self.misp_export(cache.parent, with_parent)
            if isinstance(parent, dict):
                # Something bad happened
                return parent

            event.extends_uuid = parent[-1].uuid
            parent.append(event)
            return parent

        return [event]

    def get_misp_occurrences(self, capture_uuid: str, /) -> Optional[Dict[str, Set[str]]]:
        if not self.misp.available:
            return None
        try:
            ct = self.get_crawled_tree(capture_uuid)
        except LookylooException:
            self.logger.warning(f'Unable to get the modules responses unless the tree ({capture_uuid}) is cached.')
            return None
        nodes_to_lookup = ct.root_hartree.rendered_node.get_ancestors() + [ct.root_hartree.rendered_node]
        to_return: Dict[str, Set[str]] = defaultdict(set)
        for node in nodes_to_lookup:
            hits = self.misp.lookup(node, ct.root_hartree.get_host_node_by_uuid(node.hostnode_uuid))
            for event_id, values in hits.items():
                if not isinstance(values, set):
                    continue
                to_return[event_id].update(values)
        return to_return

    def get_hashes_with_context(self, tree_uuid: str, /, algorithm: str, *, urls_only: bool=False) -> Union[Dict[str, Set[str]], Dict[str, List[URLNode]]]:
        """Build (on demand) hashes for all the ressources of the tree, using the alorighm provided by the user.
        If you just want the hashes in SHA512, use the get_hashes method, it gives you a list of hashes an they're build
        with the tree. This method is computing the hashes when you query it, so it is slower."""
        ct = self.get_crawled_tree(tree_uuid)
        hashes = ct.root_hartree.build_all_hashes(algorithm)
        if urls_only:
            return {h: {node.name for node in nodes} for h, nodes in hashes.items()}
        return hashes

    def merge_hashlookup_tree(self, tree_uuid: str, /) -> Tuple[Dict[str, Dict[str, Any]], int]:
        if not self.hashlookup.available:
            raise LookylooException('Hashlookup module not enabled.')
        hashes_tree = self.get_hashes_with_context(tree_uuid, algorithm='sha1')

        hashlookup_file = self._captures_index[tree_uuid].capture_dir / 'hashlookup.json'
        if not hashlookup_file.exists():
            ct = self.get_crawled_tree(tree_uuid)
            self.hashlookup.capture_default_trigger(ct, auto_trigger=False)

        if not hashlookup_file.exists():
            # no hits on hashlookup
            return {}, len(hashes_tree)

        with hashlookup_file.open() as f:
            hashlookup_entries = json.load(f)

        to_return: Dict[str, Dict[str, Any]] = defaultdict(dict)

        for sha1 in hashlookup_entries.keys():
            to_return[sha1]['nodes'] = hashes_tree[sha1]
            to_return[sha1]['hashlookup'] = hashlookup_entries[sha1]
        return to_return, len(hashes_tree)

    def get_hashes(self, tree_uuid: str, /, hostnode_uuid: Optional[str]=None, urlnode_uuid: Optional[str]=None) -> Set[str]:
        """Return hashes (sha512) of resources.
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

    def get_hostnames(self, tree_uuid: str, /, hostnode_uuid: Optional[str]=None, urlnode_uuid: Optional[str]=None) -> Set[str]:
        """Return all the unique hostnames:
            * of a complete tree if no hostnode_uuid and urlnode_uuid are given
            * of a HostNode if hostnode_uuid is given
            * of a URLNode if urlnode_uuid is given
        """
        if urlnode_uuid:
            node = self.get_urlnode_from_tree(tree_uuid, urlnode_uuid)
            return {node.hostname}
        elif hostnode_uuid:
            node = self.get_hostnode_from_tree(tree_uuid, hostnode_uuid)
            return {node.name}
        else:
            ct = self.get_crawled_tree(tree_uuid)
            return {node.name for node in ct.root_hartree.hostname_tree.traverse()}

    def get_urls(self, tree_uuid: str, /, hostnode_uuid: Optional[str]=None, urlnode_uuid: Optional[str]=None) -> Set[str]:
        """Return all the unique URLs:
            * of a complete tree if no hostnode_uuid and urlnode_uuid are given
            * of a HostNode if hostnode_uuid is given
            * of a URLNode if urlnode_uuid is given
        """
        if urlnode_uuid:
            node = self.get_urlnode_from_tree(tree_uuid, urlnode_uuid)
            return {node.name}
        elif hostnode_uuid:
            node = self.get_hostnode_from_tree(tree_uuid, hostnode_uuid)
            return {urlnode.name for urlnode in node.urls}
        else:
            ct = self.get_crawled_tree(tree_uuid)
            return {node.name for node in ct.root_hartree.url_tree.traverse()}

    def get_hostnode_investigator(self, capture_uuid: str, /, node_uuid: str) -> Tuple[HostNode, List[Dict[str, Any]]]:
        '''Gather all the informations needed to display the Hostnode investigator popup.'''

        def normalize_known_content(h: str, /, known_content: Dict[str, Any], url: URLNode) -> Tuple[Optional[Union[str, List[Any]]], Optional[Tuple[bool, Any]]]:
            ''' There are a few different sources to figure out known vs. legitimate content,
            this method normalize it for the web interface.'''
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

        ct = self.get_crawled_tree(capture_uuid)
        hostnode = ct.root_hartree.get_host_node_by_uuid(node_uuid)

        known_content = self.context.find_known_content(hostnode)
        self.uwhois.query_whois_hostnode(hostnode)

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
                        known, legitimate = normalize_known_content(h, known_content, url)
                        if known:
                            to_append['embedded_ressources'][h]['known_content'] = known
                        elif legitimate:
                            to_append['embedded_ressources'][h]['legitimacy'] = legitimate

                known, legitimate = normalize_known_content(url.body_hash, known_content, url)
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

    def get_stats(self) -> Dict[str, List]:
        '''Gather statistics about the lookyloo instance'''
        today = date.today()
        calendar_week = today.isocalendar()[1]

        stats_dict = {'submissions': 0, 'submissions_with_redirects': 0, 'redirects': 0}
        stats: Dict[int, Dict[int, Dict[str, Any]]] = {}
        weeks_stats: Dict[int, Dict] = {}

        for cache in self.sorted_capture_cache():
            date_submission: datetime = cache.timestamp

            if date_submission.year not in stats:
                stats[date_submission.year] = {}
            if date_submission.month not in stats[date_submission.year]:
                stats[date_submission.year][date_submission.month] = defaultdict(dict, **stats_dict)
                stats[date_submission.year][date_submission.month]['uniq_urls'] = set()
            stats[date_submission.year][date_submission.month]['submissions'] += 1
            stats[date_submission.year][date_submission.month]['uniq_urls'].add(cache.url)
            if len(cache.redirects) > 0:
                stats[date_submission.year][date_submission.month]['submissions_with_redirects'] += 1
                stats[date_submission.year][date_submission.month]['redirects'] += len(cache.redirects)
                stats[date_submission.year][date_submission.month]['uniq_urls'].update(cache.redirects)

            if ((date_submission.year == today.year and calendar_week - 1 <= date_submission.isocalendar()[1] <= calendar_week)
                    or (calendar_week == 1 and date_submission.year == today.year - 1 and date_submission.isocalendar()[1] in [52, 53])):
                if date_submission.isocalendar()[1] not in weeks_stats:
                    weeks_stats[date_submission.isocalendar()[1]] = defaultdict(dict, **stats_dict)
                    weeks_stats[date_submission.isocalendar()[1]]['uniq_urls'] = set()
                weeks_stats[date_submission.isocalendar()[1]]['submissions'] += 1
                weeks_stats[date_submission.isocalendar()[1]]['uniq_urls'].add(cache.url)
                if len(cache.redirects) > 0:
                    weeks_stats[date_submission.isocalendar()[1]]['submissions_with_redirects'] += 1
                    weeks_stats[date_submission.isocalendar()[1]]['redirects'] += len(cache.redirects)
                    weeks_stats[date_submission.isocalendar()[1]]['uniq_urls'].update(cache.redirects)

        statistics: Dict[str, List] = {'weeks': [], 'years': []}
        for week_number in sorted(weeks_stats.keys()):
            week_stat = weeks_stats[week_number]
            urls = week_stat.pop('uniq_urls')
            week_stat['week_number'] = week_number
            week_stat['uniq_urls'] = len(urls)
            week_stat['uniq_domains'] = len(uniq_domains(urls))
            statistics['weeks'].append(week_stat)

        for year in sorted(stats.keys()):
            year_stats: Dict[str, Union[int, List]] = {'year': year, 'months': [], 'yearly_submissions': 0, 'yearly_redirects': 0}
            for month in sorted(stats[year].keys()):
                month_stats = stats[year][month]
                urls = month_stats.pop('uniq_urls')
                month_stats['month_number'] = month
                month_stats['uniq_urls'] = len(urls)
                month_stats['uniq_domains'] = len(uniq_domains(urls))
                year_stats['months'].append(month_stats)  # type: ignore

                year_stats['yearly_submissions'] += month_stats['submissions']
                year_stats['yearly_redirects'] += month_stats['redirects']
            statistics['years'].append(year_stats)
        return statistics
