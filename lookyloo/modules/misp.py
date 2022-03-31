#!/usr/bin/env python3

import logging
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Union, TYPE_CHECKING

import requests
from har2tree import HostNode, URLNode, Har2TreeError
from pymisp import MISPAttribute, MISPEvent, PyMISP
from pymisp.tools import FileObject, URLObject

from ..default import get_config, get_homedir
from ..helpers import get_public_suffix_list
if TYPE_CHECKING:
    from ..capturecache import CaptureCache


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
                    # NOTE: POST the event as published publishes inline, which can tak a long time.
                    # Here, we POST as not published, and trigger the publishing in a second call.
                    background_publish = event.published
                    if background_publish:
                        event.published = False
                    new_event = self.client.add_event(event, pythonify=True)
                    if background_publish and isinstance(new_event, MISPEvent):
                        self.client.publish(new_event)
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

    def __misp_add_ips_to_URLObject(self, obj: URLObject, hostname_tree: HostNode) -> None:
        hosts = obj.get_attributes_by_relation('host')
        if hosts:
            hostnodes = hostname_tree.search_nodes(name=hosts[0].value)
            if hostnodes and hasattr(hostnodes[0], 'resolved_ips'):
                obj.add_attributes('ip', *hostnodes[0].resolved_ips)

    def export(self, cache: 'CaptureCache', is_public_instance: bool=False) -> MISPEvent:
        '''Export a capture in MISP format. You can POST the return of this method
        directly to a MISP instance and it will create an event.'''
        public_domain = get_config('generic', 'public_domain')
        event = MISPEvent()
        event.info = f'Lookyloo Capture ({cache.url})'
        lookyloo_link: MISPAttribute = event.add_attribute('link', f'https://{public_domain}/tree/{cache.uuid}')  # type: ignore
        if not is_public_instance:
            lookyloo_link.distribution = 0

        initial_url = URLObject(cache.url)
        initial_url.comment = 'Submitted URL'
        self.__misp_add_ips_to_URLObject(initial_url, cache.tree.root_hartree.hostname_tree)

        redirects: List[URLObject] = []
        for nb, url in enumerate(cache.redirects):
            if url == cache.url:
                continue
            obj = URLObject(url)
            obj.comment = f'Redirect {nb}'
            self.__misp_add_ips_to_URLObject(obj, cache.tree.root_hartree.hostname_tree)
            redirects.append(obj)
        if redirects:
            redirects[-1].comment = f'Last redirect ({nb})'

        if redirects:
            prec_object = initial_url
            for u_object in redirects:
                prec_object.add_reference(u_object, 'redirects-to')
                prec_object = u_object

        initial_obj = event.add_object(initial_url)
        initial_obj.add_reference(lookyloo_link, 'captured-by', 'Capture on lookyloo')

        for u_object in redirects:
            event.add_object(u_object)
        final_redirect = event.objects[-1]

        try:
            fo = FileObject(pseudofile=cache.tree.root_hartree.rendered_node.body, filename=cache.tree.root_hartree.rendered_node.filename)
            fo.comment = 'Content received for the final redirect (before rendering)'
            fo.add_reference(final_redirect, 'loaded-by', 'URL loading that content')
            event.add_object(fo)
        except Har2TreeError:
            pass
        except AttributeError:
            # No `body` in rendered node
            pass
        return event
