#!/usr/bin/env python3

from __future__ import annotations

import asyncio
import contextlib
import gzip
import json
import logging
import os
import pickle
import pickletools
import signal
import sys
import time

from collections import OrderedDict
from collections.abc import Mapping
from datetime import datetime, timedelta
from functools import _CacheInfo as CacheInfo
from logging import LoggerAdapter
from pathlib import Path
from typing import Any
from collections.abc import MutableMapping, Iterator

import dns.rdatatype

from dns.resolver import Cache
from dns.asyncresolver import Resolver
from har2tree import CrawledTree, Har2TreeError, HarFile
from pyipasnhistory import IPASNHistory  # type: ignore[attr-defined]
from redis import Redis

from .context import Context
from .helpers import (get_captures_dir, is_locked, load_pickle_tree, get_pickle_path,
                      remove_pickle_tree, get_indexing, mimetype_to_generic, CaptureSettings,
                      global_proxy_for_requests, get_useragent_for_requests)
from .default import LookylooException, try_make_file, get_config
from .exceptions import MissingCaptureDirectory, NoValidHarFile, MissingUUID, TreeNeedsRebuild, InvalidCaptureSetting
from .modules import Cloudflare


class LookylooCacheLogAdapter(LoggerAdapter):  # type: ignore[type-arg]
    """
    Prepend log entry with the UUID of the capture
    """
    def process(self, msg: str, kwargs: MutableMapping[str, Any]) -> tuple[str, MutableMapping[str, Any]]:
        if self.extra:
            return '[{}] {}'.format(self.extra['uuid'], msg), kwargs
        return msg, kwargs


def safe_make_datetime(dt: str) -> datetime:
    try:
        return datetime.strptime(dt, '%Y-%m-%dT%H:%M:%S.%f%z')
    except ValueError:
        # If the microsecond is missing (0), it fails
        return datetime.strptime(dt, '%Y-%m-%dT%H:%M:%S%z')


class CaptureCache():
    __slots__ = ('uuid', 'title', 'timestamp', 'url', 'redirects', 'capture_dir',
                 'error', 'no_index', 'parent',
                 'user_agent', 'referer', 'logger')

    def __init__(self, cache_entry: dict[str, Any]):
        logger = logging.getLogger(f'{self.__class__.__name__}')
        logger.setLevel(get_config('generic', 'loglevel'))
        __default_cache_keys: tuple[str, str, str, str, str, str] = ('uuid', 'title', 'timestamp',
                                                                     'url', 'redirects', 'capture_dir')
        if 'uuid' not in cache_entry or 'capture_dir' not in cache_entry:
            raise LookylooException(f'The capture is deeply broken: {cache_entry}')
        self.uuid: str = cache_entry['uuid']
        self.logger = LookylooCacheLogAdapter(logger, {'uuid': self.uuid})

        self.capture_dir: Path = Path(cache_entry['capture_dir'])

        if url := cache_entry.get('url'):
            # This entry *should* be present even if there is an error.
            self.url: str = url.strip()

        # if the cache doesn't have the keys in __default_cache_keys, it must have an error.
        # if it has neither all the expected entries, nor error, we must raise an exception
        if (not all(key in cache_entry.keys() for key in __default_cache_keys)
                and not cache_entry.get('error')):
            missing = set(__default_cache_keys) - set(cache_entry.keys())
            raise LookylooException(f'Missing keys ({missing}), no error message. It should not happen.')

        if cache_entry.get('title') is not None:
            self.title: str = cache_entry['title']

        if cache_entry.get('timestamp'):
            if isinstance(cache_entry['timestamp'], str):
                self.timestamp: datetime = safe_make_datetime(cache_entry['timestamp'])
            elif isinstance(cache_entry['timestamp'], datetime):
                self.timestamp = cache_entry['timestamp']

        self.redirects: list[str] = json.loads(cache_entry['redirects']) if cache_entry.get('redirects') else []

        # Error without all the keys in __default_cache_keys was fatal.
        # if the keys in __default_cache_keys are present, it was an HTTP error and we still need to pass the error along
        self.error: str | None = cache_entry.get('error')
        self.no_index: bool = True if cache_entry.get('no_index') in [1, '1'] else False
        self.parent: str | None = cache_entry.get('parent')
        self.user_agent: str | None = cache_entry.get('user_agent')
        self.referer: str | None = cache_entry.get('referer')

    def search(self, query: str) -> bool:
        if self.title and query in self.title:
            return True
        if self.url and query in self.url:
            return True
        if self.referer and query in self.referer:
            return True
        if self.redirects and any(query in redirect for redirect in self.redirects):
            return True
        return False

    @property
    def tree_ready(self) -> bool:
        return bool(get_pickle_path(self.capture_dir))

    @property
    def tree(self) -> CrawledTree:
        if not self.capture_dir.exists():
            raise MissingCaptureDirectory(f'The capture {self.uuid} does not exists in {self.capture_dir}.')
        while is_locked(self.capture_dir):
            time.sleep(5)
        return load_pickle_tree(self.capture_dir, self.capture_dir.stat().st_mtime, self.logger)

    @property
    def categories(self) -> set[str]:
        categ_file = self.capture_dir / 'categories'
        if categ_file.exists():
            with categ_file.open() as f:
                return {line.strip() for line in f.readlines()}
        return set()

    @categories.setter
    def categories(self, categories: set[str]) -> None:
        categ_file = self.capture_dir / 'categories'
        with categ_file.open('w') as f:
            f.write('\n'.join(categories))

    @property
    def capture_settings(self) -> CaptureSettings | None:
        capture_settings_file = self.capture_dir / 'capture_settings.json'
        if capture_settings_file.exists():
            try:
                with capture_settings_file.open() as f:
                    return CaptureSettings(**json.load(f))
            except InvalidCaptureSetting as e:
                self.logger.warning(f'[In file!] Invalid capture settings for {self.uuid}: {e}')
        return None


def serialize_sets(obj: Any) -> Any:
    if isinstance(obj, set):
        return list(obj)

    return obj


class CapturesIndex(Mapping):  # type: ignore[type-arg]

    def __init__(self, redis: Redis, contextualizer: Context | None=None, maxsize: int | None=None) -> None:  # type: ignore[type-arg]
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.redis = redis
        self.contextualizer = contextualizer
        self.__cache_max_size = maxsize
        self.__cache: dict[str, CaptureCache] = OrderedDict()
        self.timeout = get_config('generic', 'max_tree_create_time')
        self.expire_cache_sec = int(timedelta(days=get_config('generic', 'archive')).total_seconds()) * 2

        self.dnsresolver: Resolver = Resolver()
        self.dnsresolver.cache = Cache(900)
        self.dnsresolver.timeout = 4
        self.dnsresolver.lifetime = 6
        self.query_types = [dns.rdatatype.RdataType.A, dns.rdatatype.RdataType.AAAA,
                            dns.rdatatype.RdataType.SOA, dns.rdatatype.RdataType.NS,
                            dns.rdatatype.RdataType.MX]

        ipasnhistory_config = get_config('modules', 'IPASNHistory')
        self.ipasnhistory: IPASNHistory | None = None
        if ipasnhistory_config.get('enabled'):
            try:
                self.ipasnhistory = IPASNHistory(ipasnhistory_config['url'],
                                                 useragent=get_useragent_for_requests(),
                                                 proxies=global_proxy_for_requests())
                if not self.ipasnhistory.is_up:
                    self.ipasnhistory = None
                self.logger.info('IPASN History ready')
            except Exception as e:
                # Unable to setup IPASN History
                self.logger.warning(f'Unable to setup IPASN History: {e}')
                self.ipasnhistory = None
        else:
            self.logger.info('IPASN History disabled')

        self.cloudflare: Cloudflare = Cloudflare()
        if not self.cloudflare.available:
            self.logger.warning('Unable to setup Cloudflare.')
        else:
            self.logger.info('Cloudflare ready')

    @property
    def cached_captures(self) -> set[str]:
        return set(self.__cache.keys())

    def __getitem__(self, uuid: str) -> CaptureCache:
        if self.__cache_max_size is not None and len(self.__cache) > self.__cache_max_size:
            self.__cache.popitem()
        if uuid in self.__cache:
            if self.__cache[uuid].capture_dir.exists():
                return self.__cache[uuid]
            del self.__cache[uuid]
        capture_dir = self._get_capture_dir(uuid)
        cached = self.redis.hgetall(capture_dir)
        if cached:
            cc = CaptureCache(cached)
            # NOTE: checking for pickle to exist may be a bad idea here.
            if (cc.capture_dir.exists()
                    and ((cc.capture_dir / 'tree.pickle.gz').exists()
                         or (cc.capture_dir / 'tree.pickle').exists())):
                self.__cache[uuid] = cc
                return self.__cache[uuid]
        self.__cache[uuid] = asyncio.run(self._set_capture_cache(capture_dir))
        return self.__cache[uuid]

    def __iter__(self) -> Iterator[dict[str, CaptureCache]]:
        return iter(self.__cache)  # type: ignore[arg-type]

    def __len__(self) -> int:
        return len(self.__cache)

    def reload_cache(self, uuid: str) -> None:
        if uuid in self.__cache:
            self.redis.delete(str(self.__cache[uuid].capture_dir))
            del self.__cache[uuid]
        else:
            capture_dir = self._get_capture_dir(uuid)
            self.redis.delete(capture_dir)

    def remove_pickle(self, uuid: str) -> None:
        if cache := self.get_capture_cache_quick(uuid):
            remove_pickle_tree(cache.capture_dir)
        if uuid in self.__cache:
            del self.__cache[uuid]

    def rebuild_all(self) -> None:
        for uuid, cache in self.__cache.items():
            remove_pickle_tree(cache.capture_dir)
        self.redis.flushdb()
        self.__cache = {}

    def lru_cache_status(self) -> CacheInfo:
        return load_pickle_tree.cache_info()

    def lru_cache_clear(self) -> None:
        load_pickle_tree.cache_clear()

    def get_capture_cache_quick(self, uuid: str) -> CaptureCache | None:
        """Get the CaptureCache for the UUID if it exists in redis,
        WARNING: it doesn't check if the path exists, nor if the pickle is there
        """
        logger = LookylooCacheLogAdapter(self.logger, {'uuid': uuid})
        if uuid in self.cached_captures:
            self.redis.expire(str(self.__cache[uuid].capture_dir), self.expire_cache_sec)
            return self.__cache[uuid]
        try:
            capture_dir = self._get_capture_dir(uuid)
            self.redis.expire(capture_dir, self.expire_cache_sec)
            if cached := self.redis.hgetall(capture_dir):
                return CaptureCache(cached)
        except MissingUUID as e:
            logger.warning(f'Unable to get CaptureCache: {e}')
        except Exception as e:
            logger.error(f'Unable to get CaptureCache: {e}')
        return None

    def _get_capture_dir(self, uuid: str) -> str:
        # Try to get from the recent captures cache in redis
        capture_dir = self.redis.hget('lookup_dirs', uuid)
        if capture_dir:
            if os.path.exists(capture_dir):
                return capture_dir
            # The capture was either removed or archived, cleaning up
            p = self.redis.pipeline()
            p.hdel('lookup_dirs', uuid)
            p.zrem('recent_captures', uuid)
            p.zrem('recent_captures_public', uuid)
            p.delete(capture_dir)
            p.execute()

        # Try to get from the archived captures cache in redis
        capture_dir = self.redis.hget('lookup_dirs_archived', uuid)
        if capture_dir:
            if os.path.exists(capture_dir):
                return capture_dir
            # The capture was removed, remove the UUID
            self.redis.hdel('lookup_dirs_archived', uuid)
            self.redis.delete(capture_dir)
            self.logger.warning(f'UUID ({uuid}) linked to a missing directory ({capture_dir}).')
            raise MissingCaptureDirectory(f'UUID ({uuid}) linked to a missing directory ({capture_dir}).')
        raise MissingUUID(f'Unable to find UUID "{uuid}".')

    def _prepare_hostnode_tree_for_icons(self, tree: CrawledTree) -> None:
        for node in tree.root_hartree.hostname_tree.traverse():
            for url in node.urls:
                if 'mimetype' in url.features:
                    generic_type = mimetype_to_generic(url.mimetype)
                    if generic_type not in node.features:
                        node.add_feature(generic_type, 1)
                    else:
                        node.add_feature(generic_type, getattr(node, generic_type) + 1)
                if 'posted_data' in url.features:
                    if 'posted_data' not in node.features:
                        node.add_feature('posted_data', 1)
                    else:
                        node.posted_data += 1
                if 'iframe' in url.features:
                    if 'iframe' not in node.features:
                        node.add_feature('iframe', 1)
                    else:
                        node.iframe += 1
                if 'redirect' in url.features:
                    if 'redirect' not in node.features:
                        node.add_feature('redirect', 1)
                    else:
                        node.redirect += 1
                if 'redirect_to_nothing' in url.features:
                    if 'redirect_to_nothing' not in node.features:
                        node.add_feature('redirect_to_nothing', 1)
                    else:
                        node.redirect_to_nothing += 1

    async def _create_pickle(self, capture_dir: Path, logger: LookylooCacheLogAdapter) -> CrawledTree:
        logger.debug(f'Creating pickle for {capture_dir}')
        with (capture_dir / 'uuid').open() as f:
            uuid = f.read().strip()

        lock_file = capture_dir / 'lock'
        if try_make_file(lock_file):
            # Lock created, we can process
            with lock_file.open('w') as f:
                f.write(f"{datetime.now().isoformat()};{os.getpid()}")
        else:
            # The pickle is being created somewhere else, wait until it's done.
            # is locked returns false if it as been set by the same process
            while is_locked(capture_dir):
                time.sleep(5)
            try:
                # this call fails if the pickle is missing, handling the case
                # where this method was called from background build
                return load_pickle_tree(capture_dir, capture_dir.stat().st_mtime, logger)
            except TreeNeedsRebuild:
                # If this exception is raised, the building failed somewhere else, let's give it another shot.
                pass

        if not (har_files := sorted(capture_dir.glob('*.har'))):
            har_files = sorted(capture_dir.glob('*.har.gz'))
        try:
            default_recursion_limit = sys.getrecursionlimit()
            with self._timeout_context():
                tree = CrawledTree(har_files, uuid)
                self._prepare_hostnode_tree_for_icons(tree)
            await self.__resolve_dns(tree, logger)
            if self.contextualizer:
                self.contextualizer.contextualize_tree(tree)
        except Har2TreeError as e:
            # unable to use the HAR files, get them out of the way
            for har_file in har_files:
                har_file.rename(har_file.with_suffix('.broken'))
            logger.debug(f'We got HAR files, but they are broken: {e}')
            raise NoValidHarFile(f'We got har files, but they are broken: {e}')
        except TimeoutError:
            for har_file in har_files:
                har_file.rename(har_file.with_suffix('.broken'))
            logger.warning(f'Unable to rebuild the tree for {capture_dir}, the tree took more than {self.timeout}s.')
            raise NoValidHarFile(f'We got har files, but creating a tree took more than {self.timeout}s.')
        except RecursionError as e:
            for har_file in har_files:
                har_file.rename(har_file.with_suffix('.broken'))
            logger.debug(f'Tree too deep, probably a recursive refresh: {e}.')
            raise NoValidHarFile(f'Tree too deep, probably a recursive refresh: {e}.')
        else:
            # Some pickles require a pretty high recursion limit, this kindof fixes it.
            # If the capture is really broken (generally a refresh to self), the capture
            # is discarded in the RecursionError above.
            sys.setrecursionlimit(int(default_recursion_limit * 10))
            try:
                with gzip.open(capture_dir / 'tree.pickle.gz', 'wb') as _p:
                    _p.write(pickletools.optimize(pickle.dumps(tree, protocol=5)))
            except RecursionError as e:
                logger.exception('Unable to store pickle.')
                # unable to use the HAR files, get them out of the way
                for har_file in har_files:
                    har_file.rename(har_file.with_suffix('.broken'))
                (capture_dir / 'tree.pickle.gz').unlink(missing_ok=True)
                logger.debug(f'Tree too deep, probably a recursive refresh: {e}.')
                raise NoValidHarFile(f'Tree too deep, probably a recursive refresh: {e}.\n Append /export to the URL to get the files.')
            except Exception:
                (capture_dir / 'tree.pickle.gz').unlink(missing_ok=True)
                logger.exception('Unable to store pickle.')
        finally:
            sys.setrecursionlimit(default_recursion_limit)
            lock_file.unlink(missing_ok=True)
        logger.debug(f'Pickle for {capture_dir} created.')
        return tree

    @staticmethod
    def _raise_timeout(_, __) -> None:  # type: ignore[no-untyped-def]
        raise TimeoutError

    @contextlib.contextmanager
    def _timeout_context(self) -> Iterator[None]:
        if self.timeout != 0:
            # Register a function to raise a TimeoutError on the signal.
            signal.signal(signal.SIGALRM, self._raise_timeout)
            signal.alarm(self.timeout)
            try:
                yield
            except TimeoutError as e:
                raise e
            finally:
                signal.signal(signal.SIGALRM, signal.SIG_IGN)
        else:
            yield

    async def _set_capture_cache(self, capture_dir_str: str) -> CaptureCache:
        '''Populate the redis cache for a capture. Mostly used on the index page.
        NOTE: Doesn't require the pickle.'''
        capture_dir = Path(capture_dir_str)
        try:
            with (capture_dir / 'uuid').open() as f:
                uuid = f.read().strip()
        except FileNotFoundError:
            if not os.listdir(capture_dir_str):
                # The directory is empty, removing it
                os.rmdir(capture_dir_str)
                self.logger.warning(f'Empty directory: {capture_dir_str}')
                raise MissingCaptureDirectory(f'Empty directory: {capture_dir_str}')
            self.logger.warning(f'Unable to find the UUID file in {capture_dir}.')
            raise MissingCaptureDirectory(f'Unable to find the UUID file in {capture_dir}.')

        cache: dict[str, str | int] = {'uuid': uuid, 'capture_dir': capture_dir_str}
        logger = LookylooCacheLogAdapter(self.logger, {'uuid': uuid})
        try:
            logger.debug('Trying to load the tree.')
            tree = load_pickle_tree(capture_dir, capture_dir.stat().st_mtime, logger)
            logger.debug('Successfully loaded the tree.')
        except NoValidHarFile:
            logger.debug('Unable to rebuild the tree, the HAR files are broken.')
        except TreeNeedsRebuild:
            try:
                logger.debug('The tree needs to be rebuilt.')
                tree = await self._create_pickle(capture_dir, logger)
                # Force the reindexing in the public and full index (if enabled)
                get_indexing().force_reindex(uuid)
                if get_config('generic', 'index_everything'):
                    get_indexing(full=True).force_reindex(uuid)
            except NoValidHarFile as e:
                logger.warning(f'Unable to rebuild the tree for {capture_dir}, the HAR files are not usable: {e}.')
                tree = None
                cache['error'] = f'Unable to rebuild the tree for {uuid}, the HAR files are not usable: {e}'

        capture_settings_file = capture_dir / 'capture_settings.json'
        if capture_settings_file.exists():
            with capture_settings_file.open() as f:
                _s = f.read()
                try:
                    capture_settings = json.loads(_s)
                    capture_settings.get('url')
                except AttributeError:
                    # That's if we have broken dumps that are twice json encoded
                    capture_settings = json.load(capture_settings)
            if capture_settings.get('url') and capture_settings['url'] is not None:
                cache['url'] = capture_settings['url'].strip()

        if (capture_dir / 'error.txt').exists():
            # Something went wrong
            with (capture_dir / 'error.txt').open() as _error:
                content = _error.read()
                try:
                    error_to_cache = json.loads(content)
                    if isinstance(error_to_cache, dict) and error_to_cache.get('details'):
                        error_to_cache = error_to_cache.get('details')
                except json.decoder.JSONDecodeError:
                    # old format
                    error_to_cache = content
                cache['error'] = f'The capture {uuid} ({capture_dir.name}) has an error: {error_to_cache}'

        if not (har_files := sorted(capture_dir.rglob('*.har'))):
            har_files = sorted(capture_dir.rglob('*.har.gz'))
        if har_files:
            try:
                har = HarFile(har_files[0], uuid)
                try:
                    # If encoding fails, the cache cannot be stored in redis and it barfs.
                    cache['title'] = har.initial_title.encode().decode()
                except UnicodeEncodeError:
                    cache['title'] = har.initial_title.encode('utf-8', 'backslashreplace').decode()
                cache['timestamp'] = har.initial_start_time
                cache['redirects'] = json.dumps(tree.redirects) if tree else ''
                cache['user_agent'] = har.root_user_agent if har.root_user_agent else 'No User Agent.'
                if 'url' not in cache:
                    # if all went well, we already filled that one above.
                    cache['url'] = har.root_url.strip()
                if har.root_referrer:
                    cache['referer'] = har.root_referrer
            except Har2TreeError as e:
                cache['error'] = str(e)
        else:
            if 'error' not in cache:
                cache['error'] = f'No har files in {capture_dir.name}'

        if (cache.get('error')
                and isinstance(cache['error'], str)
                and 'HTTP Error' not in cache['error']
                and 'Unable to resolve' not in cache['error']
                and 'Capturing ressources on private IPs' not in cache['error']
                and "No har files in" not in cache['error']):
            logger.info(cache['error'])

        if (capture_dir / 'no_index').exists():
            # If the folders claims anonymity
            cache['no_index'] = 1

        if (capture_dir / 'parent').exists():
            # The capture was initiated from an other one
            with (capture_dir / 'parent').open() as f:
                cache['parent'] = f.read().strip()

        p = self.redis.pipeline()
        # if capture_dir.is_relative_to(get_captures_dir()):  # Requires python 3.9
        if capture_dir_str.startswith(str(get_captures_dir())):
            p.hset('lookup_dirs', uuid, capture_dir_str)
        else:
            p.hset('lookup_dirs_archived', uuid, capture_dir_str)

        p.delete(capture_dir_str)
        p.hset(capture_dir_str, mapping=cache)  # type: ignore[arg-type]
        # NOTE: just expire it from redis after it's not on the index anymore.
        # Avoids to have an evergrowing cache.
        p.expire(capture_dir_str, self.expire_cache_sec)

        to_return = CaptureCache(cache)
        if hasattr(to_return, 'timestamp') and to_return.timestamp:
            p.zadd('recent_captures', {uuid: to_return.timestamp.timestamp()})
            if not to_return.no_index:
                # public capture
                p.zadd('recent_captures_public', {uuid: to_return.timestamp.timestamp()})

        p.execute()
        return to_return

    async def __resolve_dns(self, ct: CrawledTree, logger: LookylooCacheLogAdapter) -> None:
        '''Resolves all domains of the tree, keeps A (IPv4), AAAA (IPv6), and CNAME entries
        and store them in ips.json and cnames.json, in the capture directory.
        Updates the nodes of the tree accordingly so the information is available.
        '''

        def _build_cname_chain(known_cnames: dict[str, str], hostname: str) -> list[str]:
            '''Returns a list of CNAMEs starting from one hostname.
            The CNAMEs resolutions are made in `_resolve_dns`. A hostname can have a CNAME entry
            and the CNAME entry can have an other CNAME entry, and so on multiple times.
            This method loops over the hostnames until there are no CNAMES.'''
            cnames: list[str] = []
            to_search = hostname
            while True:
                if not known_cnames.get(to_search):
                    break
                cnames.append(known_cnames[to_search])
                to_search = known_cnames[to_search]
            return cnames

        async def _dns_query(hostname: str, domain: str, semaphore: asyncio.Semaphore) -> None:
            async with semaphore:
                for qt in self.query_types:
                    try:
                        await self.dnsresolver.resolve(hostname, qt, search=True, raise_on_no_answer=False)
                        await self.dnsresolver.resolve(domain, qt, search=True, raise_on_no_answer=False)
                    except Exception as e:
                        logger.info(f'Unable to resolve DNS {hostname} - {qt}: {e}')

        cnames_path = ct.root_hartree.har.path.parent / 'cnames.json'
        ips_path = ct.root_hartree.har.path.parent / 'ips.json'
        ipasn_path = ct.root_hartree.har.path.parent / 'ipasn.json'
        soa_path = ct.root_hartree.har.path.parent / 'soa.json'
        ns_path = ct.root_hartree.har.path.parent / 'nameservers.json'
        mx_path = ct.root_hartree.har.path.parent / 'mx.json'

        host_cnames: dict[str, str] = {}
        if cnames_path.exists():
            try:
                with cnames_path.open() as f:
                    host_cnames = json.load(f)
            except json.decoder.JSONDecodeError:
                # The json is broken, delete and re-trigger the requests
                host_cnames = {}

        host_ips: dict[str, dict[str, set[str]]] = {}
        if ips_path.exists():
            try:
                with ips_path.open() as f:
                    host_ips = json.load(f)
                    for host, _ips in host_ips.items():
                        if 'v4' in _ips and 'v6' in _ips:
                            _ips['v4'] = set(_ips['v4'])
                            _ips['v6'] = set(_ips['v6'])
                        else:
                            # old format
                            old_ips = _ips
                            _ips = {'v4': set(), 'v6': set()}
                            for ip in old_ips:
                                if '.' in ip:
                                    _ips['v4'].add(ip)
                                elif ':' in ip:
                                    _ips['v6'].add(ip)
                        host_ips[host] = _ips
            except json.decoder.JSONDecodeError:
                # The json is broken, delete and re-trigger the requests
                host_ips = {}

        ipasn: dict[str, dict[str, str]] = {}
        if ipasn_path.exists():
            try:
                with ipasn_path.open() as f:
                    ipasn = json.load(f)
            except json.decoder.JSONDecodeError:
                # The json is broken, delete and re-trigger the requests
                ipasn = {}

        host_soa: dict[str, tuple[str, str]] = {}
        if soa_path.exists():
            try:
                with soa_path.open() as f:
                    host_soa = {k: (v[0], v[1]) for k, v in json.load(f).items() if len(v) == 2}
            except json.decoder.JSONDecodeError:
                # The json is broken, delete and re-trigger the requests
                host_soa = {}

        host_mx: dict[str, set[str]] = {}
        if mx_path.exists():
            try:
                with mx_path.open() as f:
                    host_mx = {k: set(v) for k, v in json.load(f).items()}
            except json.decoder.JSONDecodeError:
                # The json is broken, delete and re-trigger the requests
                host_mx = {}

        host_ns: dict[str, set[str]] = {}
        if ns_path.exists():
            try:
                with ns_path.open() as f:
                    host_ns = {k: set(v) for k, v in json.load(f).items()}
            except json.decoder.JSONDecodeError:
                # The json is broken, delete and re-trigger the requests
                host_ns = {}

        _all_ips = set()
        _all_hostnames: set[tuple[str, str]] = {
            (node.name, node.domain) for node in ct.root_hartree.hostname_tree.traverse()
            if (not getattr(node, 'hostname_is_ip', False)
                and not getattr(node, 'file_on_disk', False)
                and node.name
                and not (node.tld in ('onion', 'i2p')))}
        self.dnsresolver.cache.flush()
        logger.info(f'Resolving DNS: {len(_all_hostnames)} hostnames.')
        semaphore = asyncio.Semaphore(20)
        all_requests = [_dns_query(hostname, domain, semaphore) for hostname, domain in _all_hostnames]
        # run all the requests, cache them and let the rest of the code deal.
        # And if a few fail due to network issues, we retry later.
        await asyncio.gather(*all_requests)
        logger.info('Done resolving DNS.')
        for node in ct.root_hartree.hostname_tree.traverse():
            if ('hostname_is_ip' in node.features and node.hostname_is_ip
                    or (node.name and any([node.name.endswith('onion'), node.name.endswith('i2p')]))):
                continue

            # A and AAAA records, they contain the CNAME responses, even if there are no A or AAAA records.
            try:
                a_response = await self.dnsresolver.resolve(node.name, dns.rdatatype.RdataType.A, search=True, raise_on_no_answer=False)
            except Exception as e:
                logger.info(f'[A record] Unable to resolve: {e}')
                a_response = None

            try:
                aaaa_response = await self.dnsresolver.resolve(node.name, dns.rdatatype.RdataType.AAAA, search=True, raise_on_no_answer=False)
            except Exception as e:
                logger.info(f'[AAAA record] Unable to resolve: {e}')
                aaaa_response = None

            if a_response is None and aaaa_response is None:
                # No A, AAAA or CNAME record, skip node
                continue

            answers = []
            if a_response:
                answers += a_response.response.answer
            if aaaa_response:
                answers += aaaa_response.response.answer

            for answer in answers:
                name_to_cache = str(answer.name).rstrip('.')
                if name_to_cache not in host_ips:
                    host_ips[name_to_cache] = {'v4': set(), 'v6': set()}

                if answer.rdtype == dns.rdatatype.RdataType.A:
                    _all_ips |= {str(b) for b in answer}
                    host_ips[name_to_cache]['v4'] |= {str(b) for b in answer}
                elif answer.rdtype == dns.rdatatype.RdataType.AAAA:
                    _all_ips |= {str(b) for b in answer}
                    host_ips[name_to_cache]['v6'] |= {str(b) for b in answer}
                elif answer.rdtype == dns.rdatatype.RdataType.CNAME:
                    host_cnames[name_to_cache] = str(answer[0].target).rstrip('.')

            try:
                soa_response = await self.dnsresolver.resolve(node.name, dns.rdatatype.RdataType.SOA, search=True, raise_on_no_answer=False)
                for answer in soa_response.response.answer + soa_response.response.authority:
                    if answer.rdtype != dns.rdatatype.RdataType.SOA:
                        continue
                    name_to_cache = str(answer.name).rstrip('.')
                    host_soa[node.name] = (name_to_cache, str(answer[0]))
                    node.add_feature('soa', host_soa[node.name])
                    # Should only have one
                    break
            except Exception as e:
                logger.info(f'[SOA record] Unable to resolve: {e}')

            # NS, and MX records that may not be in the response for the hostname
            # trigger the request on domains if needed.
            try:
                mx_response = await self.dnsresolver.resolve(node.name, dns.rdatatype.RdataType.MX, search=True, raise_on_no_answer=True)
            except dns.resolver.NoAnswer:
                # logger.info(f'No MX record for {node.name}.')
                # Try again on the domain
                try:
                    mx_response = await self.dnsresolver.resolve(node.domain, dns.rdatatype.RdataType.MX, search=True, raise_on_no_answer=True)
                except dns.resolver.NoAnswer:
                    logger.debug(f'No MX record for {node.domain}.')
                    mx_response = None
                except Exception as e:
                    logger.info(f'[MX record] Unable to resolve: {e}')
                    mx_response = None
            except Exception as e:
                logger.info(f'[MX record] Unable to resolve: {e}')
                mx_response = None

            if mx_response:
                for answer in mx_response.response.answer:
                    if answer.rdtype != dns.rdatatype.RdataType.MX:
                        continue
                    name_to_cache = str(answer.name).rstrip('.')
                    if name_to_cache not in host_mx:
                        host_mx[name_to_cache] = set()
                    try:
                        host_mx[name_to_cache] |= {str(b.exchange) for b in answer}
                        node.add_feature('mx', (name_to_cache, host_mx[name_to_cache]))
                        break
                    except Exception as e:
                        logger.info(f'[MX record] broken: {e}')

            # We must always have a NS record, otherwise, we couldn't resolve.
            # Let's keep trying removing the first part of the hostname until we get an answer.
            ns_response = None
            try:
                ns_response = await self.dnsresolver.resolve(node.name, dns.rdatatype.RdataType.NS, search=True, raise_on_no_answer=True)
            except dns.resolver.NoAnswer:
                # Try again on the domain and keep trying until we get an answer.
                if to_query := node.domain:
                    while ns_response is None:
                        try:
                            ns_response = await self.dnsresolver.resolve(to_query, dns.rdatatype.RdataType.NS, search=True, raise_on_no_answer=True)
                        except dns.resolver.NoAnswer:
                            if '.' not in to_query:
                                # We are at the root, we cannot go further.
                                break
                            to_query = to_query[to_query.index('.') + 1:]
                        except Exception as e:
                            logger.info(f'[NS record] Unable to resolve: {e}')
                            break
            except Exception as e:
                logger.info(f'[NS record] Unable to resolve: {e}')

            if ns_response:
                for answer in ns_response.response.answer:
                    name_to_cache = str(answer.name).rstrip('.')
                    if name_to_cache not in host_ns:
                        host_ns[name_to_cache] = set()
                    host_ns[name_to_cache] |= {str(b) for b in answer}
                    node.add_feature('ns', (name_to_cache, host_ns[name_to_cache]))
                    break

            if cnames := _build_cname_chain(host_cnames, node.name):
                last_cname = cnames[-1]
                node.add_feature('cname', cnames)
                if last_cname in host_ips:
                    node.add_feature('resolved_ips', host_ips[last_cname])
            else:
                if node.name in host_ips:
                    node.add_feature('resolved_ips', host_ips[node.name])

            _all_nodes_ips = set()
            if 'resolved_ips' in node.features:
                if 'v4' in node.resolved_ips and 'v6' in node.resolved_ips:
                    _all_nodes_ips = set(node.resolved_ips['v4']) | set(node.resolved_ips['v6'])
                else:
                    # old format
                    _all_nodes_ips = node.resolved_ips

            if not _all_nodes_ips:
                # No IPs in the node.
                continue

            # check if the resolved IPs are cloudflare IPs
            if self.cloudflare.available:
                if hits := {ip: hit for ip, hit in self.cloudflare.ips_lookup(_all_nodes_ips).items() if hit}:
                    node.add_feature('cloudflare', hits)

            # trigger ipasnhistory cache in that loop
            if self.ipasnhistory:
                for _ in range(3):
                    try:
                        self.ipasnhistory.mass_cache([{'ip': ip} for ip in _all_nodes_ips])
                        break
                    except Exception as e:
                        logger.warning(f'Unable to submit IPs to IPASNHistory, retrying: {e}')
                        await asyncio.sleep(1)
                else:
                    logger.warning('Unable to submit IPs to IPASNHistory, disabling.')
                    self.ipasnhistory = None

        # for performances reasons, we need to batch the requests to IPASN History,
        # and re-traverse the tree.
        if self.ipasnhistory:
            if query_ips := [{'ip': ip} for ip in _all_ips]:
                try:
                    ipasn_responses = self.ipasnhistory.mass_query(query_ips)
                    if 'responses' in ipasn_responses:
                        for response in ipasn_responses['responses']:
                            ip = response['meta']['ip']
                            if responses := list(response['response'].values()):
                                if ip not in ipasn and responses[0]:
                                    ipasn[ip] = responses[0]

                except Exception as e:
                    logger.warning(f'Unable to query IPASNHistory: {e}')
        if ipasn:
            # retraverse tree to populate it with the features
            for node in ct.root_hartree.hostname_tree.traverse():
                if 'resolved_ips' not in node.features:
                    continue
                if 'v4' in node.resolved_ips and 'v6' in node.resolved_ips:
                    _all_nodes_ips = set(node.resolved_ips['v4']) | set(node.resolved_ips['v6'])
                else:
                    # old format
                    _all_nodes_ips = node.resolved_ips
                if ipasn_entries := {ip: ipasn[ip] for ip in _all_nodes_ips if ip in ipasn}:
                    node.add_feature('ipasn', ipasn_entries)

        with cnames_path.open('w') as f:
            json.dump(host_cnames, f)
        with ips_path.open('w') as f:
            json.dump(host_ips, f, default=serialize_sets)
        with ipasn_path.open('w') as f:
            json.dump(ipasn, f)
        with soa_path.open('w') as f:
            json.dump(host_soa, f, default=serialize_sets)
        with ns_path.open('w') as f:
            json.dump(host_ns, f, default=serialize_sets)
        with mx_path.open('w') as f:
            json.dump(host_mx, f, default=serialize_sets)

        logger.info('Done with DNS.')
