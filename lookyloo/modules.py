#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List, Union, Iterable, Set
from datetime import date
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import time
import logging
import socket
import re

from .helpers import get_homedir, get_config, get_public_suffix_list, get_useragent_for_requests
from .exceptions import ConfigError

import vt  # type: ignore
from vt.error import APIError  # type: ignore
from pysanejs import SaneJS
from pyeupi import PyEUPI
from pymisp import PyMISP, MISPEvent, MISPAttribute
import requests

from har2tree import CrawledTree, HostNode, URLNode, Har2TreeError


class MISP():

    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        if not config.get('apikey'):
            self.available = False
            self.logger.info('Module not enabled.')
            return

        self.available = True
        self.enable_lookup = False
        self.enable_push = False
        self.allow_auto_trigger = False
        try:
            self.client = PyMISP(url=config['url'], key=config['apikey'],
                                 ssl=config['verify_tls_cert'], timeout=config['timeout'])
        except Exception as e:
            self.available = False
            self.logger.warning(f'Unable to connect to MISP: {e}')
            return

        if config.get('enable_lookup'):
            self.enable_lookup = True
        if config.get('enable_push'):
            self.enable_push = True
        if config.get('allow_auto_trigger'):
            self.allow_auto_trigger = True
        self.default_tags: List[str] = config.get('default_tags')  # type: ignore
        self.auto_publish = config.get('auto_publish')
        self.storage_dir_misp = get_homedir() / 'misp'
        self.storage_dir_misp.mkdir(parents=True, exist_ok=True)
        self.psl = get_public_suffix_list()

    def get_fav_tags(self):
        return self.client.tags(pythonify=True, favouritesOnly=1)

    def _prepare_push(self, to_push: Union[List[MISPEvent], MISPEvent], allow_duplicates: bool=False, auto_publish: Optional[bool]=False) -> Union[List[MISPEvent], Dict]:
        '''Adds the pre-configured information as required by the instance.
        If duplicates aren't allowed, they will be automatically skiped and the
        extends_uuid key in the next element in the list updated'''
        if isinstance(to_push, MISPEvent):
            events = [to_push]
        else:
            events = to_push
        events_to_push = []
        existing_uuid_to_extend = None
        for event in events:
            if not allow_duplicates:
                existing_event = self.get_existing_event(event.attributes[0].value)
                if existing_event:
                    existing_uuid_to_extend = existing_event.uuid
                    continue
            if existing_uuid_to_extend:
                event.extends_uuid = existing_uuid_to_extend
                existing_uuid_to_extend = None

            for tag in self.default_tags:
                event.add_tag(tag)
            if auto_publish:
                event.publish()
            events_to_push.append(event)
        return events_to_push

    def push(self, to_push: Union[List[MISPEvent], MISPEvent], allow_duplicates: bool=False, auto_publish: Optional[bool]=None) -> Union[List[MISPEvent], Dict]:
        if auto_publish is None:
            auto_publish = self.auto_publish
        if self.available and self.enable_push:
            events = self._prepare_push(to_push, allow_duplicates, auto_publish)
            if not events:
                return {'error': 'All the events are already on the MISP instance.'}
            if isinstance(events, Dict):
                return {'error': events}
            to_return = []
            for event in events:
                new_event = self.client.add_event(event, pythonify=True)
                if isinstance(new_event, MISPEvent):
                    to_return.append(new_event)
                else:
                    return {'error': new_event}
            return to_return
        else:
            return {'error': 'Module not available or push not enabled.'}

    def get_existing_event_url(self, permaurl: str) -> Optional[str]:
        attributes = self.client.search('attributes', value=permaurl, limit=1, page=1, pythonify=True)
        if not attributes or not isinstance(attributes[0], MISPAttribute):
            return None
        url = f'{self.client.root_url}/events/{attributes[0].event_id}'
        return url

    def get_existing_event(self, permaurl: str) -> Optional[MISPEvent]:
        attributes = self.client.search('attributes', value=permaurl, limit=1, page=1, pythonify=True)
        if not attributes or not isinstance(attributes[0], MISPAttribute):
            return None
        event = self.client.get_event(attributes[0].event_id, pythonify=True)
        if isinstance(event, MISPEvent):
            return event
        return None

    def lookup(self, node: URLNode, hostnode: HostNode) -> Union[Dict[str, Set[str]], Dict[str, Any]]:
        if self.available and self.enable_lookup:
            tld = self.psl.get_tld(hostnode.name)
            domain = re.sub(f'.{tld}$', '', hostnode.name).split('.')[-1]
            to_lookup = [node.name, hostnode.name, f'{domain}.{tld}'] + hostnode.resolved_ips
            if hasattr(hostnode, 'cnames'):
                to_lookup += hostnode.cnames
            if not node.empty_response:
                to_lookup.append(node.body_hash)
            if attributes := self.client.search(controller='attributes', value=to_lookup,
                                                enforce_warninglist=True, pythonify=True):
                if isinstance(attributes, list):
                    to_return: Dict[str, Set[str]] = defaultdict(set)
                    # NOTE: We have MISPAttribute in that list
                    for a in attributes:
                        to_return[a.event_id].add(a.value)  # type: ignore
                    return to_return
                else:
                    # The request returned an error
                    return attributes  # type: ignore
            return {'info': 'No hits.'}
        else:
            return {'error': 'Module not available or lookup not enabled.'}


class UniversalWhois():

    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        if not config.get('enabled'):
            self.available = False
            self.logger.info('Module not enabled.')
            return
        self.server = config.get('ipaddress')
        self.port = config.get('port')
        self.allow_auto_trigger = False
        if config.get('allow_auto_trigger'):
            self.allow_auto_trigger = True

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.server, self.port))
        except Exception as e:
            self.available = False
            self.logger.warning(f'Unable to connect to uwhois ({self.server}:{self.port}): {e}')
            return
        self.available = True

    def query_whois_hostnode(self, hostnode: HostNode) -> None:
        if hasattr(hostnode, 'resolved_ips'):
            for ip in hostnode.resolved_ips:
                self.whois(ip)
        if hasattr(hostnode, 'cnames'):
            for cname in hostnode.cnames:
                self.whois(cname)
        self.whois(hostnode.name)

    def capture_default_trigger(self, crawled_tree: CrawledTree, /, *, force: bool=False, auto_trigger: bool=False) -> None:
        '''Run the module on all the nodes up to the final redirect'''
        if not self.available:
            return None
        if auto_trigger and not self.allow_auto_trigger:
            return None

        try:
            hostnode = crawled_tree.root_hartree.get_host_node_by_uuid(crawled_tree.root_hartree.rendered_node.hostnode_uuid)
        except Har2TreeError as e:
            self.logger.warning(e)
        else:
            self.query_whois_hostnode(hostnode)
            for n in hostnode.get_ancestors():
                self.query_whois_hostnode(n)

    def whois(self, query: str) -> str:
        if not self.available:
            return ''
        bytes_whois = b''
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.server, self.port))
            sock.sendall('{}\n'.format(query).encode())
            while True:
                data = sock.recv(2048)
                if not data:
                    break
                bytes_whois += data
        to_return = bytes_whois.decode()
        return to_return


class SaneJavaScript():

    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        if not config.get('enabled'):
            self.available = False
            self.logger.info('Module not enabled.')
            return
        self.client = SaneJS()
        if not self.client.is_up:
            self.available = False
            return
        self.available = True
        self.allow_auto_trigger = False
        if config.get('allow_auto_trigger'):
            self.allow_auto_trigger = True
        self.storage_dir = get_homedir() / 'sanejs'
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def hashes_lookup(self, sha512: Union[Iterable[str], str], force: bool=False) -> Dict[str, List[str]]:
        if isinstance(sha512, str):
            hashes: Iterable[str] = [sha512]
        else:
            hashes = sha512

        today_dir = self.storage_dir / date.today().isoformat()
        today_dir.mkdir(parents=True, exist_ok=True)
        sanejs_unknowns = today_dir / 'unknown'
        unknown_hashes = set()
        if sanejs_unknowns.exists():
            with sanejs_unknowns.open() as f:
                unknown_hashes = set(line.strip() for line in f.readlines())

        to_return: Dict[str, List[str]] = {}

        if force:
            to_lookup = hashes
        else:
            to_lookup = [h for h in hashes if (h not in unknown_hashes
                                               and not (today_dir / h).exists())]
        has_new_unknown = False
        for h in to_lookup:
            try:
                response = self.client.sha512(h)
            except Exception as e:
                self.logger.warning(f'Something went wrong. Query: {h} - {e}')
                continue

            if 'error' in response:
                # Server not ready
                break
            if 'response' in response and response['response']:
                cached_path = today_dir / h
                with cached_path.open('w') as f:
                    json.dump(response['response'], f)
                to_return[h] = response['response']
            else:
                has_new_unknown = True
                unknown_hashes.add(h)

        for h in hashes:
            cached_path = today_dir / h
            if h in unknown_hashes or h in to_return:
                continue
            elif cached_path.exists():
                with cached_path.open() as f:
                    to_return[h] = json.load(f)

        if has_new_unknown:
            with sanejs_unknowns.open('w') as f:
                f.writelines(f'{h}\n' for h in unknown_hashes)

        return to_return


class PhishingInitiative():

    def __init__(self, config: Dict[str, Any]):
        if not config.get('apikey'):
            self.available = False
            return

        self.available = True
        self.autosubmit = False
        self.allow_auto_trigger = False
        self.client = PyEUPI(config['apikey'])

        if config.get('allow_auto_trigger'):
            self.allow_auto_trigger = True

        if config.get('autosubmit'):
            self.autosubmit = True

        self.storage_dir_eupi = get_homedir() / 'eupi'
        self.storage_dir_eupi.mkdir(parents=True, exist_ok=True)

    def __get_cache_directory(self, url: str) -> Path:
        m = hashlib.md5()
        m.update(url.encode())
        return self.storage_dir_eupi / m.hexdigest()

    def get_url_lookup(self, url: str) -> Optional[Dict[str, Any]]:
        url_storage_dir = self.__get_cache_directory(url)
        if not url_storage_dir.exists():
            return None
        cached_entries = sorted(url_storage_dir.glob('*'), reverse=True)
        if not cached_entries:
            return None

        with cached_entries[0].open() as f:
            return json.load(f)

    def capture_default_trigger(self, crawled_tree: CrawledTree, /, *, force: bool=False, auto_trigger: bool=False) -> Dict:
        '''Run the module on all the nodes up to the final redirect'''
        if not self.available:
            return {'error': 'Module not available'}
        if auto_trigger and not self.allow_auto_trigger:
            return {'error': 'Auto trigger not allowed on module'}

        if crawled_tree.redirects:
            for redirect in crawled_tree.redirects:
                self.url_lookup(redirect, force)
        else:
            self.url_lookup(crawled_tree.root_hartree.har.root_url, force)
        return {'success': 'Module triggered'}

    def url_lookup(self, url: str, force: bool=False) -> None:
        '''Lookup an URL on Phishing Initiative
        Note: force means 2 things:
            * (re)scan of the URL
            * re fetch the object from Phishing Initiative even if we already did it today

        Note: the URL will only be sent for scan if autosubmit is set to true in the config
        '''
        if not self.available:
            raise ConfigError('PhishingInitiative not available, probably no API key')

        url_storage_dir = self.__get_cache_directory(url)
        url_storage_dir.mkdir(parents=True, exist_ok=True)
        pi_file = url_storage_dir / date.today().isoformat()

        scan_requested = False
        if self.autosubmit and force:
            self.client.post_submission(url, comment='Received on Lookyloo')
            scan_requested = True

        if not force and pi_file.exists():
            return

        for _ in range(3):
            url_information = self.client.lookup(url)
            if not url_information['results']:
                # No results, that should not happen (?)
                break
            if url_information['results'][0]['tag'] == -1:
                # Not submitted
                if not self.autosubmit:
                    break
                if not scan_requested:
                    self.client.post_submission(url, comment='Received on Lookyloo')
                    scan_requested = True
                time.sleep(1)
            else:
                with pi_file.open('w') as _f:
                    json.dump(url_information, _f)
                break


class VirusTotal():

    def __init__(self, config: Dict[str, Any]):
        if not config.get('apikey'):
            self.available = False
            return

        self.available = True
        self.autosubmit = False
        self.allow_auto_trigger = False
        self.client = vt.Client(config['apikey'])

        if config.get('allow_auto_trigger'):
            self.allow_auto_trigger = True

        if config.get('autosubmit'):
            self.autosubmit = True

        self.storage_dir_vt = get_homedir() / 'vt_url'
        self.storage_dir_vt.mkdir(parents=True, exist_ok=True)

    def __get_cache_directory(self, url: str) -> Path:
        url_id = vt.url_id(url)
        m = hashlib.md5()
        m.update(url_id.encode())
        return self.storage_dir_vt / m.hexdigest()

    def get_url_lookup(self, url: str) -> Optional[Dict[str, Any]]:
        url_storage_dir = self.__get_cache_directory(url)
        if not url_storage_dir.exists():
            return None
        cached_entries = sorted(url_storage_dir.glob('*'), reverse=True)
        if not cached_entries:
            return None

        with cached_entries[0].open() as f:
            return json.load(f)

    def capture_default_trigger(self, crawled_tree: CrawledTree, /, *, force: bool=False, auto_trigger: bool=False) -> Dict:
        '''Run the module on all the nodes up to the final redirect'''
        if not self.available:
            return {'error': 'Module not available'}
        if auto_trigger and not self.allow_auto_trigger:
            return {'error': 'Auto trigger not allowed on module'}

        if crawled_tree.redirects:
            for redirect in crawled_tree.redirects:
                self.url_lookup(redirect, force)
        else:
            self.url_lookup(crawled_tree.root_hartree.har.root_url, force)
        return {'success': 'Module triggered'}

    def url_lookup(self, url: str, force: bool=False) -> None:
        '''Lookup an URL on VT
        Note: force means 2 things:
            * (re)scan of the URL
            * re fetch the object from VT even if we already did it today

        Note: the URL will only be sent for scan if autosubmit is set to true in the config
        '''
        if not self.available:
            raise ConfigError('VirusTotal not available, probably no API key')

        url_storage_dir = self.__get_cache_directory(url)
        url_storage_dir.mkdir(parents=True, exist_ok=True)
        vt_file = url_storage_dir / date.today().isoformat()

        scan_requested = False
        if self.autosubmit and force:
            self.client.scan_url(url)
            scan_requested = True

        if not force and vt_file.exists():
            return

        url_id = vt.url_id(url)
        for _ in range(3):
            try:
                url_information = self.client.get_object(f"/urls/{url_id}")
                with vt_file.open('w') as _f:
                    json.dump(url_information.to_dict(), _f)
                break
            except APIError as e:
                if not self.autosubmit:
                    break
                if not scan_requested and e.code == 'NotFoundError':
                    self.client.scan_url(url)
                    scan_requested = True
            time.sleep(5)


class UrlScan():

    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        if not config.get('apikey'):
            self.available = False
            return

        self.available = True
        self.autosubmit = False
        self.allow_auto_trigger = False
        self.client = requests.session()
        self.client.headers['User-Agent'] = get_useragent_for_requests()
        self.client.headers['API-Key'] = config['apikey']
        self.client.headers['Content-Type'] = 'application/json'

        if config.get('allow_auto_trigger'):
            self.allow_auto_trigger = True

        if config.get('autosubmit'):
            self.autosubmit = True

        if config.get('force_visibility'):
            # Cases:
            # 1. False: unlisted for hidden captures / public for others
            # 2. "key": default visibility defined on urlscan.io
            # 3. "public", "unlisted", "private": is set for all submissions
            self.force_visibility = config['force_visibility']
        else:
            self.force_visibility = False

        if self.force_visibility not in [False, 'key', 'public', 'unlisted', 'private']:
            self.logger.warning("Invalid value for force_visibility, default to False (unlisted for hidden captures / public for others).")
            self.force_visibility = False

        self.storage_dir_urlscan = get_homedir() / 'urlscan'
        self.storage_dir_urlscan.mkdir(parents=True, exist_ok=True)

    def __get_cache_directory(self, url: str, useragent: str, referer: str) -> Path:
        m = hashlib.md5()
        to_hash = f'{url}{useragent}{referer}'
        m.update(to_hash.encode())
        return self.storage_dir_urlscan / m.hexdigest()

    def get_url_submission(self, capture_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        url_storage_dir = self.__get_cache_directory(capture_info['url'],
                                                     capture_info['user_agent'],
                                                     capture_info['referer']) / 'submit'
        if not url_storage_dir.exists():
            return None
        cached_entries = sorted(url_storage_dir.glob('*'), reverse=True)
        if not cached_entries:
            return None

        with cached_entries[0].open() as f:
            return json.load(f)

    def capture_default_trigger(self, capture_info: Dict[str, Any], /, visibility: str, *, force: bool=False, auto_trigger: bool=False) -> Dict:
        '''Run the module on the initial URL'''
        if not self.available:
            return {'error': 'Module not available'}
        if auto_trigger and not self.allow_auto_trigger:
            # NOTE: if auto_trigger is true, it means the request comes from the
            # auto trigger feature (disabled by default)
            # Each module can disable auto-trigger to avoid depleating the
            # API limits.
            return {'error': 'Auto trigger not allowed on module'}

        self.url_submit(capture_info, visibility, force)
        return {'success': 'Module triggered'}

    def __submit_url(self, url: str, useragent: str, referer: str, visibility: str) -> Dict:
        data = {'customagent': useragent, 'referer': referer}

        if not url.startswith('http'):
            url = f'http://{url}'
        data['url'] = url

        if self.force_visibility is False:
            data["visibility"] = visibility
        elif self.force_visibility in ["public", "unlisted", "private"]:
            data["visibility"] = self.force_visibility
        else:
            # default to key config on urlscan.io website
            pass
        response = self.client.post('https://urlscan.io/api/v1/scan/', json=data)
        response.raise_for_status()
        return response.json()

    def __url_result(self, uuid: str) -> Dict:
        response = self.client.get(f'https://urlscan.io/api/v1/result/{uuid}')
        response.raise_for_status()
        return response.json()

    def url_submit(self, capture_info: Dict[str, Any], visibility: str, force: bool=False) -> Dict:
        '''Lookup an URL on urlscan.io
        Note: force means 2 things:
            * (re)scan of the URL
            * re-fetch the object from urlscan.io even if we already did it today

        Note: the URL will only be submitted if autosubmit is set to true in the config
        '''
        if not self.available:
            raise ConfigError('UrlScan not available, probably no API key')

        url_storage_dir = self.__get_cache_directory(capture_info['url'],
                                                     capture_info['user_agent'],
                                                     capture_info['referer']) / 'submit'
        url_storage_dir.mkdir(parents=True, exist_ok=True)
        urlscan_file_submit = url_storage_dir / date.today().isoformat()

        if urlscan_file_submit.exists():
            if not force:
                with urlscan_file_submit.open('r') as _f:
                    return json.load(_f)
        elif self.autosubmit:
            # submit is allowed and we either force it, or it's just allowed
            try:
                response = self.__submit_url(capture_info['url'],
                                             capture_info['user_agent'],
                                             capture_info['referer'],
                                             visibility)
            except requests.exceptions.HTTPError as e:
                return {'error': e}
            with urlscan_file_submit.open('w') as _f:
                json.dump(response, _f)
            return response
        return {'error': 'Submitting is not allowed by the configuration'}

    def url_result(self, capture_info: Dict[str, Any]):
        '''Get the result from a submission.'''
        submission = self.get_url_submission(capture_info)
        if submission and 'uuid' in submission:
            uuid = submission['uuid']
            if (self.storage_dir_urlscan / f'{uuid}.json').exists():
                with (self.storage_dir_urlscan / f'{uuid}.json').open() as _f:
                    return json.load(_f)
            try:
                result = self.__url_result(uuid)
            except requests.exceptions.HTTPError as e:
                return {'error': e}
            with (self.storage_dir_urlscan / f'{uuid}.json').open('w') as _f:
                json.dump(result, _f)
            return result
        return {'error': 'Submission incomplete or unavailable.'}
