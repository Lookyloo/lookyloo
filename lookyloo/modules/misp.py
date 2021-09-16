#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Union

import requests
from har2tree import HostNode, URLNode
from pymisp import MISPAttribute, MISPEvent, PyMISP

from ..helpers import get_config, get_homedir, get_public_suffix_list


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
                try:
                    new_event = self.client.add_event(event, pythonify=True)
                except requests.exceptions.ReadTimeout:
                    return {'error': 'The connection to MISP timed out, try increasing the timeout in the config.'}
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
