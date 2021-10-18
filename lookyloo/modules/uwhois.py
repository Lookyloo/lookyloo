#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import socket
from typing import Any, Dict

from har2tree import CrawledTree, Har2TreeError, HostNode

from ..default import get_config


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
