#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List, Union, Iterable
from datetime import date
import hashlib
import json
from pathlib import Path
import time
import logging
import socket

from .helpers import get_homedir, get_config
from .exceptions import ConfigError

import vt  # type: ignore
from vt.error import APIError  # type: ignore
from pysanejs import SaneJS
from pyeupi import PyEUPI
from pymisp import PyMISP, MISPEvent, MISPAttribute

from har2tree import CrawledTree, HostNode


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

    def get_fav_tags(self):
        return self.client.tags(pythonify=True, favouritesOnly=1)

    def _prepare_push(self, to_push: Union[List[MISPEvent], MISPEvent], allow_duplicates: bool=False, auto_publish: bool=False) -> Union[List[MISPEvent], Dict]:
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

        hostnode = crawled_tree.root_hartree.get_host_node_by_uuid(crawled_tree.root_hartree.rendered_node.hostnode_uuid)
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

    def capture_default_trigger(self, crawled_tree: CrawledTree, /, *, force: bool=False, auto_trigger: bool=False) -> None:
        '''Run the module on all the nodes up to the final redirect'''
        if not self.available:
            return None
        if auto_trigger and not self.allow_auto_trigger:
            return None

        if crawled_tree.redirects:
            for redirect in crawled_tree.redirects:
                self.url_lookup(redirect, force)
        else:
            self.url_lookup(crawled_tree.root_hartree.har.root_url, force)

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

        for i in range(3):
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

    def capture_default_trigger(self, crawled_tree: CrawledTree, /, *, force: bool=False, auto_trigger: bool=False) -> None:
        '''Run the module on all the nodes up to the final redirect'''
        if not self.available:
            return None
        if auto_trigger and not self.allow_auto_trigger:
            return None

        if crawled_tree.redirects:
            for redirect in crawled_tree.redirects:
                self.url_lookup(redirect, force)
        else:
            self.url_lookup(crawled_tree.root_hartree.har.root_url, force)

    def url_lookup(self, url: str, force: bool=False) -> None:
        '''Lookup an URL on VT
        Note: force means 2 things:
            * (re)scan of the URL
            * re fetch the object from VT even if we already did it today

        Note: the URL will only be sent for scan if autosubmit is set to true in the config
        '''
        if not self.available:
            raise ConfigError('VirusTotal not available, probably no API key')

        url_id = vt.url_id(url)
        url_storage_dir = self.__get_cache_directory(url)
        url_storage_dir.mkdir(parents=True, exist_ok=True)
        vt_file = url_storage_dir / date.today().isoformat()

        scan_requested = False
        if self.autosubmit and force:
            self.client.scan_url(url)
            scan_requested = True

        if not force and vt_file.exists():
            return

        for i in range(3):
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
