#!/usr/bin/env python3

from __future__ import annotations

from datetime import datetime
import re

from io import BytesIO
from collections import defaultdict
from collections.abc import Mapping
from typing import Any, TYPE_CHECKING
from collections.abc import Iterator

import requests
from har2tree import HostNode, URLNode, Har2TreeError
from pymisp import MISPAttribute, MISPEvent, PyMISP, MISPTag
from pymisp.tools import FileObject, URLObject

from ..default import get_config, get_homedir
from ..exceptions import ModuleError
from ..helpers import get_public_suffix_list, global_proxy_for_requests

from .abstractmodule import AbstractModule

if TYPE_CHECKING:
    from ..capturecache import CaptureCache


class MISPs(Mapping, AbstractModule):  # type: ignore[type-arg]

    def module_init(self) -> bool:
        if not self.config.get('default'):
            self.logger.info('No default instance configured, disabling MISP.')
            return False
        if not self.config.get('instances'):
            self.logger.warning('No MISP instances configured, disabling MISP.')
            return False

        self.default_instance = self.config['default']

        if self.default_instance not in self.config['instances']:
            self.logger.warning(f"The default MISP instance ({self.default_instance}) is missing in the instances ({', '.join(self.config['instances'].keys())}), disabling MISP.")
            return False

        self.__misps = {}
        for instance_name, instance_config in self.config['instances'].items():
            if misp_connector := MISP(config=instance_config):
                if misp_connector.available:
                    self.__misps[instance_name] = misp_connector
                else:
                    self.logger.warning(f"MISP '{instance_name}' isn't available.")
            else:
                self.logger.warning(f"Unable to initialize the connector to '{instance_name}'. It won't be available.")

        if not self.__misps.get(self.default_instance) or not self.__misps[self.default_instance].available:
            self.logger.warning("Unable to initialize the connector to the default MISP instance, disabling MISP.")
            return False

        return True

    @property
    def has_public_misp(self) -> bool:
        return not all(misp.admin_only for misp in self.__misps.values())

    def has_lookup(self, as_admin: bool) -> bool:
        if as_admin:
            return any(misp.enable_lookup for misp in self.__misps.values())
        return any(misp.enable_lookup and not misp.admin_only for misp in self.__misps.values())

    def has_push(self, as_admin: bool) -> bool:
        if as_admin:
            return any(misp.enable_push for misp in self.__misps.values())
        return any(misp.enable_push and not misp.admin_only for misp in self.__misps.values())

    def __getitem__(self, name: str) -> MISP:
        return self.__misps[name]

    def __iter__(self) -> Iterator[dict[str, MISP]]:
        return iter(self.__misps)

    def __len__(self) -> int:
        return len(self.__misps)

    @property
    def default_misp(self) -> MISP:
        return self.__misps[self.default_instance]

    def export(self, cache: CaptureCache, is_public_instance: bool=False,
               submitted_filename: str | None=None,
               submitted_file: BytesIO | None=None) -> MISPEvent:
        '''Export a capture in MISP format. You can POST the return of this method
        directly to a MISP instance and it will create an event.'''
        public_domain = get_config('generic', 'public_domain')
        event = MISPEvent()

        # Add the catrgories as tags
        if cache.categories:
            for category in cache.categories:
                event.add_tag(category)

        if cache.url.startswith('file://'):
            filename = cache.url.rsplit('/', 1)[-1]
            event.info = f'Lookyloo Capture ({filename})'
            # Create file object as initial
            if hasattr(cache.tree.root_hartree.url_tree, 'body'):
                # The file could be viewed in the browser
                filename = cache.tree.root_hartree.url_tree.name
                pseudofile = cache.tree.root_hartree.url_tree.body
            elif submitted_filename:
                # Impossible to get the file from the HAR.
                filename = submitted_filename
                pseudofile = submitted_file
            else:
                raise ModuleError('We must have a file here.')

            initial_file = FileObject(pseudofile=pseudofile, filename=filename)
            initial_file.comment = 'This is a capture of a file, rendered in the browser'
            initial_file.first_seen = cache.timestamp
            initial_obj = event.add_object(initial_file)
        else:
            event.info = f'Lookyloo Capture ({cache.url})'
            initial_url = URLObject(cache.url)
            initial_url.comment = 'Submitted URL'
            initial_url.first_seen = cache.timestamp
            self.__misp_add_ips_to_URLObject(initial_url, cache.tree.root_hartree.hostname_tree)
            initial_obj = event.add_object(initial_url)

        lookyloo_link: MISPAttribute = event.add_attribute('link', f'https://{public_domain}/tree/{cache.uuid}')  # type: ignore[assignment]
        if not is_public_instance:
            lookyloo_link.distribution = 0
        lookyloo_link.first_seen = cache.timestamp
        initial_obj.add_reference(lookyloo_link, 'captured-by', 'Capture on lookyloo')

        redirects: list[URLObject] = []
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
            prec_object = initial_obj
            for u_object in redirects:
                prec_object.add_reference(u_object, 'redirects-to')
                prec_object = u_object

        for u_object in redirects:
            event.add_object(u_object)
        final_redirect = event.objects[-1]

        try:
            fo = FileObject(pseudofile=cache.tree.root_hartree.rendered_node.body, filename=cache.tree.root_hartree.rendered_node.filename)
            fo.comment = 'Content received for the final redirect (before rendering)'
            fo.add_reference(final_redirect, 'loaded-by', 'URL loading that content')
            fo.first_seen = cache.tree.root_hartree.rendered_node.start_time
            if hasattr(cache.tree.root_hartree.rendered_node, 'domhash'):
                fo.add_attribute('dom-hash', cache.tree.root_hartree.rendered_node.domhash)
                final_redirect.add_attribute('dom-hash', cache.tree.root_hartree.rendered_node.domhash)
            event.add_object(fo)
        except Har2TreeError:
            pass
        except AttributeError:
            # No `body` in rendered node
            pass
        return event

    def __misp_add_ips_to_URLObject(self, obj: URLObject, hostname_tree: HostNode) -> None:
        hosts = obj.get_attributes_by_relation('host')
        if hosts:
            if hostnodes := hostname_tree.search_nodes(name=hosts[0].value):
                first_host = hostnodes[0]
                obj.first_seen = first_host.urls[0].start_time
                if hasattr(first_host, 'resolved_ips'):
                    if isinstance(first_host.resolved_ips, dict):
                        if ipsv4 := first_host.resolved_ips.get('v4'):
                            obj.add_attributes('ip', *ipsv4)
                        if ipsv6 := first_host.resolved_ips.get('v6'):
                            obj.add_attributes('ip', *ipsv6)
                    elif isinstance(first_host.resolved_ips, list) and first_host.resolved_ips:
                        # This shouldn't happen, but we have some very old
                        # captures and that was the old format.
                        obj.add_attributes('ip', *first_host.resolved_ips)


class MISP(AbstractModule):

    def module_init(self) -> bool:
        if not self.config.get('apikey'):
            self.logger.info(f'No API key: {self.config}.')
            return False

        try:
            self.client = PyMISP(url=self.config['url'], key=self.config['apikey'],
                                 ssl=self.config['verify_tls_cert'], timeout=self.config['timeout'],
                                 proxies=global_proxy_for_requests(),
                                 tool='Lookyloo')
        except Exception as e:
            self.logger.warning(f'Unable to connect to MISP: {e}')
            return False

        self.enable_lookup = bool(self.config.get('enable_lookup', False))
        self.enable_push = bool(self.config.get('enable_push', False))

        self.default_tags: list[str] = self.config.get('default_tags')  # type: ignore[assignment]
        self.auto_publish = bool(self.config.get('auto_publish', False))
        self.storage_dir_misp = get_homedir() / 'misp'
        self.storage_dir_misp.mkdir(parents=True, exist_ok=True)
        self.psl = get_public_suffix_list()
        return True

    def get_fav_tags(self) -> dict[Any, Any] | list[MISPTag]:
        return self.client.tags(pythonify=True, favouritesOnly=1)

    def _prepare_push(self, to_push: list[MISPEvent] | MISPEvent, allow_duplicates: bool=False, auto_publish: bool | None=False) -> list[MISPEvent] | dict[str, str]:
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
                existing_event = self.__get_existing_event(event.attributes[0].value)
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

    def push(self, to_push: list[MISPEvent] | MISPEvent, as_admin: bool, *, allow_duplicates: bool=False,
             auto_publish: bool | None=None) -> list[MISPEvent] | dict[Any, Any]:
        if not self.available:
            return {'error': 'Module not available.'}
        if not self.enable_push:
            return {'error': 'Push not enabled.'}
        if self.admin_only and not as_admin:
            return {'error': 'Admin only module, cannot push.'}

        if auto_publish is None:
            auto_publish = self.auto_publish

        events = self._prepare_push(to_push, allow_duplicates, auto_publish)
        if not events:
            return {'error': 'All the events are already on the MISP instance.'}
        if isinstance(events, dict):
            return {'error': events}
        to_return = []
        for event in events:
            try:
                # NOTE: POST the event as published publishes inline, which can tak a long time.
                # Here, we POST as not published, and trigger the publishing in a second call.
                if hasattr(event, 'published'):
                    background_publish = event.published
                else:
                    background_publish = False
                if background_publish:
                    event.published = False
                new_event = self.client.add_event(event, pythonify=True)
                if background_publish and isinstance(new_event, MISPEvent):
                    self.client.publish(new_event)
            except requests.Timeout:
                return {'error': 'The connection to MISP timed out, try increasing the timeout in the config.'}
            if isinstance(new_event, MISPEvent):
                to_return.append(new_event)
            else:
                return {'error': new_event}
        return to_return

    def get_existing_event_url(self, permaurl: str) -> str | None:
        attributes = self.client.search('attributes', value=permaurl, limit=1, page=1, pythonify=True)
        if not attributes or not isinstance(attributes, list) or not isinstance(attributes[0], MISPAttribute):
            return None
        url = f'{self.client.root_url}/events/{attributes[0].event_id}'
        return url

    def __get_existing_event(self, permaurl: str) -> MISPEvent | None:
        attributes = self.client.search('attributes', value=permaurl, limit=1, page=1, pythonify=True)
        if not attributes or not isinstance(attributes, list) or not isinstance(attributes[0], MISPAttribute):
            return None
        event = self.client.get_event(attributes[0].event_id, pythonify=True)
        if isinstance(event, MISPEvent):
            return event
        return None

    def lookup(self, node: URLNode, hostnode: HostNode, as_admin: bool) -> dict[int | str, str | set[tuple[str, datetime]]]:
        if not self.available:
            return {'error': 'Module not available.'}
        if not self.enable_lookup:
            return {'error': 'Lookup not enabled.'}
        if self.admin_only and not as_admin:
            return {'error': 'Admin only module, cannot lookup.'}

        tld = self.psl.publicsuffix(hostnode.name)
        domain = re.sub(f'.{tld}$', '', hostnode.name).split('.')[-1]
        to_lookup = [node.name, hostnode.name, f'{domain}.{tld}']
        if hasattr(hostnode, 'resolved_ips'):
            if 'v4' in hostnode.resolved_ips:
                to_lookup += hostnode.resolved_ips['v4']
            if 'v6' in hostnode.resolved_ips:
                to_lookup += hostnode.resolved_ips['v6']
        if hasattr(hostnode, 'cnames'):
            to_lookup += hostnode.cnames
        if not node.empty_response:
            to_lookup.append(node.body_hash)
        if attributes := self.client.search(controller='attributes', value=to_lookup,
                                            enforce_warninglist=True, pythonify=True):
            if isinstance(attributes, list):
                to_return: dict[int, set[tuple[str, datetime]]] = defaultdict(set)
                a: MISPAttribute
                for a in attributes:  # type: ignore[assignment]
                    if isinstance(a.value, str):
                        # a.timestamp is always a datetime in this situation
                        to_return[a.event_id].add((a.value, a.timestamp))  # type: ignore[arg-type]
                    else:
                        # This shouldn't happen (?)
                        self.logger.warning(f'Unexpected value type in MISP lookup: {type(a.value)}')
                return to_return  # type: ignore[return-value]
            else:
                # The request returned an error
                return attributes  # type: ignore[return-value]
        return {'info': 'No hits.'}
