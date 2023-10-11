#!/usr/bin/env python3

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

from collections.abc import Mapping
from datetime import datetime
from functools import lru_cache
from logging import Logger, LoggerAdapter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Set, MutableMapping

import dns.rdatatype
import dns.resolver
from har2tree import CrawledTree, Har2TreeError, HarFile
from pyipasnhistory import IPASNHistory
from redis import Redis

from .context import Context
from .helpers import get_captures_dir, is_locked
from .indexing import Indexing
from .default import LookylooException, try_make_file, get_config
from .exceptions import MissingCaptureDirectory, NoValidHarFile, MissingUUID, TreeNeedsRebuild
from .modules import Cloudflare


class LookylooCacheLogAdapter(LoggerAdapter):
    """
    Prepend log entry with the UUID of the capture
    """
    def process(self, msg: str, kwargs: MutableMapping[str, Any]) -> Tuple[str, MutableMapping[str, Any]]:
        if self.extra:
            return '[{}] {}'.format(self.extra['uuid'], msg), kwargs
        return msg, kwargs


class CaptureCache():
    __slots__ = ('uuid', 'title', 'timestamp', 'url', 'redirects', 'capture_dir',
                 'error', 'no_index', 'categories', 'parent',
                 'user_agent', 'referer', 'logger')

    def __init__(self, cache_entry: Dict[str, Any]):
        logger = logging.getLogger(f'{self.__class__.__name__}')
        logger.setLevel(get_config('generic', 'loglevel'))
        __default_cache_keys: Tuple[str, str, str, str, str, str] = ('uuid', 'title', 'timestamp',
                                                                     'url', 'redirects', 'capture_dir')
        if 'uuid' not in cache_entry or 'capture_dir' not in cache_entry:
            raise LookylooException(f'The capture is deeply broken: {cache_entry}')
        self.uuid: str = cache_entry['uuid']
        self.logger = LookylooCacheLogAdapter(logger, {'uuid': self.uuid})

        self.capture_dir: Path = Path(cache_entry['capture_dir'])

        if url := cache_entry.get('url'):
            # This entry *should* be present even if there is an error.
            self.url: str = url

        # if the cache doesn't have the keys in __default_cache_keys, it must have an error.
        # if it has neither all the expected entries, nor error, we must raise an exception
        if (not all(key in cache_entry.keys() for key in __default_cache_keys)
                and not cache_entry.get('error')):
            missing = set(__default_cache_keys) - set(cache_entry.keys())
            raise LookylooException(f'Missing keys ({missing}), no error message. It should not happen.')

        if cache_entry.get('title') is not None:
            self.title: str = cache_entry['title']

        if cache_entry.get('timestamp'):
            try:
                self.timestamp: datetime = datetime.strptime(cache_entry['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z')
            except ValueError:
                # If the microsecond is missing (0), it fails
                self.timestamp = datetime.strptime(cache_entry['timestamp'], '%Y-%m-%dT%H:%M:%S%z')

        self.redirects: List[str] = json.loads(cache_entry['redirects']) if cache_entry.get('redirects') else []

        # Error without all the keys in __default_cache_keys was fatal.
        # if the keys in __default_cache_keys are present, it was an HTTP error and we still need to pass the error along
        self.error: Optional[str] = cache_entry.get('error')
        self.no_index: bool = True if cache_entry.get('no_index') in [1, '1'] else False
        self.categories: List[str] = json.loads(cache_entry['categories']) if cache_entry.get('categories') else []
        self.parent: Optional[str] = cache_entry.get('parent')
        self.user_agent: Optional[str] = cache_entry.get('user_agent')
        self.referer: Optional[str] = cache_entry.get('referer')

    @property
    def tree(self) -> CrawledTree:
        if not self.capture_dir.exists():
            raise MissingCaptureDirectory(f'The capture {self.uuid} does not exists in {self.capture_dir}.')
        return load_pickle_tree(self.capture_dir, self.capture_dir.stat().st_mtime, self.logger)


def remove_pickle_tree(capture_dir: Path) -> None:
    pickle_file = capture_dir / 'tree.pickle'
    pickle_file_gz = capture_dir / 'tree.pickle.gz'
    if pickle_file.exists():
        pickle_file.unlink()
    if pickle_file_gz.exists():
        pickle_file_gz.unlink()


@lru_cache(maxsize=64)
def load_pickle_tree(capture_dir: Path, last_mod_time: int, logger: Logger) -> CrawledTree:
    pickle_file = capture_dir / 'tree.pickle'
    pickle_file_gz = capture_dir / 'tree.pickle.gz'
    tree = None
    try:
        if pickle_file.exists():
            with pickle_file.open('rb') as _p:
                tree = pickle.load(_p)
        elif pickle_file_gz.exists():
            with gzip.open(pickle_file_gz, 'rb') as _pg:
                tree = pickle.load(_pg)
    except pickle.UnpicklingError:
        remove_pickle_tree(capture_dir)
    except EOFError:
        remove_pickle_tree(capture_dir)
    except Exception:
        logger.exception('Unexpected exception when unpickling.')
        remove_pickle_tree(capture_dir)

    if tree:
        if tree.root_hartree.har.path.exists():
            return tree
        else:
            # The capture was moved.
            remove_pickle_tree(capture_dir)

    if list(capture_dir.rglob('*.har')) or list(capture_dir.rglob('*.har.gz')):
        raise TreeNeedsRebuild('We have HAR files and need to rebuild the tree.')
    # The tree doesn't need to be rebuilt if there are no HAR files.
    raise NoValidHarFile("Couldn't find HAR files")


def serialize_sets(obj):
    if isinstance(obj, set):
        return list(obj)

    return obj


class CapturesIndex(Mapping):

    def __init__(self, redis: Redis, contextualizer: Optional[Context]=None):
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.redis = redis
        self.indexing = Indexing()
        self.contextualizer = contextualizer
        self.__cache: Dict[str, CaptureCache] = {}
        self._quick_init()
        self.timeout = get_config('generic', 'max_tree_create_time')
        try:
            self.ipasnhistory: Optional[IPASNHistory] = IPASNHistory()
            if not self.ipasnhistory.is_up:
                self.ipasnhistory = None
        except Exception as e:
            # Unable to setup IPASN History
            self.logger.warning(f'Unable to setup IPASN History: {e}')
            self.ipasnhistory = None
        try:
            self.cloudflare: Optional[Cloudflare] = Cloudflare()
            if not self.cloudflare.available:
                self.cloudflare = None
        except Exception as e:
            self.logger.warning(f'Unable to setup Cloudflare: {e}')
            self.cloudflare = None

    @property
    def cached_captures(self) -> Set[str]:
        self._quick_init()
        return set(self.__cache.keys())

    def __getitem__(self, uuid: str) -> CaptureCache:
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
        self.__cache[uuid] = self._set_capture_cache(capture_dir)
        return self.__cache[uuid]

    def __iter__(self):
        return iter(self.__cache)

    def __len__(self):
        return len(self.__cache)

    def reload_cache(self, uuid: str) -> None:
        if uuid in self.__cache:
            self.redis.delete(str(self.__cache[uuid].capture_dir))
            del self.__cache[uuid]

    def remove_pickle(self, uuid: str) -> None:
        if uuid in self.__cache:
            remove_pickle_tree(self.__cache[uuid].capture_dir)
            del self.__cache[uuid]

    def rebuild_all(self) -> None:
        for uuid, cache in self.__cache.items():
            remove_pickle_tree(cache.capture_dir)
        self.redis.flushdb()
        self.__cache = {}

    def lru_cache_status(self):
        return load_pickle_tree.cache_info()

    def _quick_init(self) -> None:
        '''Initialize the cache with a list of UUIDs, with less back and forth with redis.
        Only get recent captures.'''
        p = self.redis.pipeline()
        has_new_cached_captures = False
        for uuid, directory in self.redis.hscan_iter('lookup_dirs'):
            if uuid in self.__cache:
                continue
            has_new_cached_captures = True
            p.hgetall(directory)
        if not has_new_cached_captures:
            return
        for cache in p.execute():
            if not cache:
                continue
            try:
                cc = CaptureCache(cache)
            except LookylooException as e:
                self.logger.warning(f'Unable to initialize the cache: {e}')
                continue
            self.__cache[cc.uuid] = cc

    def _get_capture_dir(self, uuid: str) -> str:
        # Try to get from the recent captures cache in redis
        capture_dir = self.redis.hget('lookup_dirs', uuid)
        if capture_dir:
            if os.path.exists(capture_dir):
                return capture_dir
            # The capture was either removed or archived, cleaning up
            self.redis.hdel('lookup_dirs', uuid)
            self.redis.delete(capture_dir)

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
        raise MissingUUID(f'Unable to find UUID {uuid}.')

    def _create_pickle(self, capture_dir: Path, logger: LookylooCacheLogAdapter) -> CrawledTree:
        with (capture_dir / 'uuid').open() as f:
            uuid = f.read().strip()

        lock_file = capture_dir / 'lock'
        if try_make_file(lock_file):
            # Lock created, we can process
            with lock_file.open('w') as f:
                f.write(f"{datetime.now().isoformat()};{os.getpid()}")
        else:
            # The pickle is being created somewhere else, wait until it's done.
            while is_locked(capture_dir):
                time.sleep(5)
            try:
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
            self.__resolve_dns(tree, logger)
            if self.contextualizer:
                self.contextualizer.contextualize_tree(tree)
        except Har2TreeError as e:
            # unable to use the HAR files, get them out of the way
            for har_file in har_files:
                har_file.rename(har_file.with_suffix('.broken'))
            raise NoValidHarFile(f'We got har files, but they are broken: {e}')
        except TimeoutError:
            logger.warning(f'Unable to rebuild the tree for {capture_dir}, the tree took too long.')
            for har_file in har_files:
                har_file.rename(har_file.with_suffix('.broken'))
            raise NoValidHarFile(f'We got har files, but creating a tree took more than {self.timeout}s.')
        except RecursionError as e:
            raise NoValidHarFile(f'Tree too deep, probably a recursive refresh: {e}.\n Append /export to the URL to get the files.')
        else:
            # Some pickles require a pretty high recursion limit, this kindof fixes it.
            # If the capture is really broken (generally a refresh to self), the capture
            # is discarded in the RecursionError above.
            sys.setrecursionlimit(int(default_recursion_limit * 1.1))
            try:
                with gzip.open(capture_dir / 'tree.pickle.gz', 'wb') as _p:
                    _p.write(pickletools.optimize(pickle.dumps(tree, protocol=5)))
            except RecursionError as e:
                logger.exception('Unable to store pickle.')
                # unable to use the HAR files, get them out of the way
                for har_file in har_files:
                    har_file.rename(har_file.with_suffix('.broken'))
                (capture_dir / 'tree.pickle.gz').unlink(missing_ok=True)
                raise NoValidHarFile(f'Tree too deep, probably a recursive refresh: {e}.\n Append /export to the URL to get the files.')
            except Exception:
                (capture_dir / 'tree.pickle.gz').unlink(missing_ok=True)
                logger.exception('Unable to store pickle.')
        finally:
            sys.setrecursionlimit(default_recursion_limit)
            lock_file.unlink(missing_ok=True)
        return tree

    @staticmethod
    def _raise_timeout(_, __):
        raise TimeoutError

    @contextlib.contextmanager
    def _timeout_context(self):
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

    def _set_capture_cache(self, capture_dir_str: str) -> CaptureCache:
        '''Populate the redis cache for a capture. Mostly used on the index page.
        NOTE: Doesn't require the pickle.'''
        capture_dir = Path(capture_dir_str)
        with (capture_dir / 'uuid').open() as f:
            uuid = f.read().strip()

        # Get capture settings as they were submitted
        capture_settings_file = capture_dir / 'capture_settings.json'
        if capture_settings_file.exists():
            with capture_settings_file.open() as f:
                capture_settings = json.load(f)
        else:
            capture_settings = {}

        logger = LookylooCacheLogAdapter(self.logger, {'uuid': uuid})
        try:
            tree = load_pickle_tree(capture_dir, capture_dir.stat().st_mtime, logger)
        except NoValidHarFile:
            logger.debug('Unable to rebuild the tree, the HAR files are broken.')
        except TreeNeedsRebuild:
            try:
                tree = self._create_pickle(capture_dir, logger)
                self.indexing.new_internal_uuids(tree)
            except NoValidHarFile:
                logger.warning(f'Unable to rebuild the tree for {capture_dir}, the HAR files are broken.')
                tree = None

        cache: Dict[str, Union[str, int]] = {'uuid': uuid, 'capture_dir': capture_dir_str}
        if capture_settings.get('url'):
            cache['url'] = capture_settings['url']

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
                cache['title'] = har.initial_title
                cache['timestamp'] = har.initial_start_time
                cache['redirects'] = json.dumps(tree.redirects) if tree else ''
                cache['user_agent'] = har.root_user_agent if har.root_user_agent else 'No User Agent.'
                if 'url' not in cache:
                    # if all went well, we already filled that one above.
                    cache['url'] = har.root_url
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
                and "No har files in" not in cache['error']):
            logger.info(cache['error'])

        if (capture_dir / 'categories').exists():
            with (capture_dir / 'categories').open() as _categories:
                cache['categories'] = json.dumps([c.strip() for c in _categories.readlines()])

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
        p.hset(capture_dir_str, mapping=cache)  # type: ignore
        p.execute()
        return CaptureCache(cache)

    def __resolve_dns(self, ct: CrawledTree, logger: LookylooCacheLogAdapter):
        '''Resolves all domains of the tree, keeps A (IPv4), AAAA (IPv6), and CNAME entries
        and store them in ips.json and cnames.json, in the capture directory.
        Updates the nodes of the tree accordingly so the information is available.
        '''

        def _build_cname_chain(known_cnames: Dict[str, str], hostname) -> List[str]:
            '''Returns a list of CNAMEs starting from one hostname.
            The CNAMEs resolutions are made in `_resolve_dns`. A hostname can have a CNAME entry
            and the CNAME entry can have an other CNAME entry, and so on multiple times.
            This method loops over the hostnames until there are no CNAMES.'''
            cnames: List[str] = []
            to_search = hostname
            while True:
                if not known_cnames.get(to_search):
                    break
                cnames.append(known_cnames[to_search])
                to_search = known_cnames[to_search]
            return cnames

        cnames_path = ct.root_hartree.har.path.parent / 'cnames.json'
        ips_path = ct.root_hartree.har.path.parent / 'ips.json'
        ipasn_path = ct.root_hartree.har.path.parent / 'ipasn.json'

        host_cnames: Dict[str, str] = {}
        if cnames_path.exists():
            try:
                with cnames_path.open() as f:
                    host_cnames = json.load(f)
            except json.decoder.JSONDecodeError:
                # The json is broken, delete and re-trigger the requests
                host_cnames = {}

        host_ips: Dict[str, Dict[str, Set[str]]] = {}
        if ips_path.exists():
            try:
                with ips_path.open() as f:
                    host_ips = json.load(f)
            except json.decoder.JSONDecodeError:
                # The json is broken, delete and re-trigger the requests
                host_ips = {}

        ipasn: Dict[str, Dict[str, str]] = {}
        if ipasn_path.exists():
            try:
                with ipasn_path.open() as f:
                    ipasn = json.load(f)
            except json.decoder.JSONDecodeError:
                # The json is broken, delete and re-trigger the requests
                ipasn = {}

        _all_ips = set()
        for node in ct.root_hartree.hostname_tree.traverse():
            if 'hostname_is_ip' in node.features and node.hostname_is_ip:
                continue
            if node.name not in host_cnames or node.name not in host_ips:
                host_cnames[node.name] = ''
                host_ips[node.name] = {'v4': set(), 'v6': set()}
                # Resolve and cache
                for query_type in [dns.rdatatype.RdataType.A, dns.rdatatype.RdataType.AAAA]:
                    try:
                        response = dns.resolver.resolve(node.name, query_type, search=True, raise_on_no_answer=False)
                    except Exception as e:
                        logger.warning(f'Unable to resolve DNS: {e}')
                        continue
                    for answer in response.response.answer:
                        name_to_cache = str(answer.name).rstrip('.')
                        if name_to_cache not in host_ips:
                            host_ips[name_to_cache] = {'v4': set(), 'v6': set()}
                        else:
                            if 'v4' in host_ips[name_to_cache] and 'v6' in host_ips[name_to_cache]:
                                host_ips[name_to_cache]['v4'] = set(host_ips[name_to_cache]['v4'])
                                host_ips[name_to_cache]['v6'] = set(host_ips[name_to_cache]['v6'])
                            else:
                                # old format
                                old_ips = host_ips[name_to_cache]
                                host_ips[name_to_cache] = {'v4': set(), 'v6': set()}
                                for ip in old_ips:
                                    if '.' in ip:
                                        host_ips[name_to_cache]['v4'].add(ip)
                                    elif ':' in ip:
                                        host_ips[name_to_cache]['v6'].add(ip)

                        if answer.rdtype == dns.rdatatype.RdataType.CNAME:
                            host_cnames[name_to_cache] = str(answer[0].target).rstrip('.')
                        else:
                            host_cnames[name_to_cache] = ''

                        if answer.rdtype == dns.rdatatype.RdataType.A:
                            _all_ips |= {str(b) for b in answer}
                            host_ips[name_to_cache]['v4'] |= {str(b) for b in answer}
                        elif answer.rdtype == dns.rdatatype.RdataType.AAAA:
                            _all_ips |= {str(b) for b in answer}
                            host_ips[name_to_cache]['v6'] |= {str(b) for b in answer}

            if (cnames := _build_cname_chain(host_cnames, node.name)):
                node.add_feature('cname', cnames)
                if cnames[-1] in host_ips:
                    node.add_feature('resolved_ips', host_ips[cnames[-1]])
            elif node.name in host_ips:
                node.add_feature('resolved_ips', host_ips[node.name])

        cflare_hits = {}
        if self.cloudflare:
            cflare_hits = self.cloudflare.ips_lookup(_all_ips)

        if self.ipasnhistory:
            # Throw all the IPs to IPASN History for query later.
            if ips := [{'ip': ip} for ip in _all_ips]:
                try:
                    self.ipasnhistory.mass_cache(ips)
                except Exception as e:
                    logger.warning(f'Unable to submit IPs to IPASNHistory: {e}')
                else:
                    time.sleep(2)
                    ipasn_responses = self.ipasnhistory.mass_query(ips)
                    if 'responses' in ipasn_responses:
                        for response in ipasn_responses['responses']:
                            ip = response['meta']['ip']
                            r = list(response['response'].values())[0]
                            if ip not in ipasn and r:
                                ipasn[ip] = r

        if ipasn or cflare_hits:
            # retraverse tree to populate it with the features
            for node in ct.root_hartree.hostname_tree.traverse():
                if 'resolved_ips' not in node.features:
                    continue
                ipasn_entries = {}
                cflare_entries = {}
                if 'v4' in node.resolved_ips and 'v6' in node.resolved_ips:
                    _all_ips = set(node.resolved_ips['v4']) | set(node.resolved_ips['v6'])
                else:
                    # old format
                    _all_ips = node.resolved_ips
                for ip in _all_ips:
                    if ip in ipasn:
                        ipasn_entries[ip] = ipasn[ip]
                    if ip in cflare_hits and cflare_hits[ip] is True:
                        cflare_entries[ip] = True

                if ipasn_entries:
                    node.add_feature('ipasn', ipasn_entries)
                if cflare_entries:
                    node.add_feature('cloudflare', cflare_entries)

        with cnames_path.open('w') as f:
            json.dump(host_cnames, f)
        with ips_path.open('w') as f:
            json.dump(host_ips, f, default=serialize_sets)
        with ipasn_path.open('w') as f:
            json.dump(ipasn, f)
        return ct
