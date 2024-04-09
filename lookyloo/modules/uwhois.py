#!/usr/bin/env python3

from __future__ import annotations

import re
import socket

from typing import overload, Literal

from har2tree import CrawledTree, Har2TreeError, HostNode

from .abstractmodule import AbstractModule


class UniversalWhois(AbstractModule):

    def module_init(self) -> bool:
        if not self.config.get('enabled'):
            self.logger.info('Not enabled.')
            return False

        self.server = self.config.get('ipaddress')
        self.port = self.config.get('port')
        self.allow_auto_trigger = bool(self.config.get('allow_auto_trigger', False))

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.server, self.port))
        except Exception as e:
            self.logger.warning(f'Unable to connect to uwhois ({self.server}:{self.port}): {e}')
            return False
        return True

    def query_whois_hostnode(self, hostnode: HostNode) -> None:
        if hasattr(hostnode, 'resolved_ips'):
            ip: str
            if 'v4' in hostnode.resolved_ips and 'v6' in hostnode.resolved_ips:
                _all_ips = set(hostnode.resolved_ips['v4']) | set(hostnode.resolved_ips['v6'])
            else:
                # old format
                _all_ips = hostnode.resolved_ips
            for ip in _all_ips:
                self.whois(ip, contact_email_only=False)
        if hasattr(hostnode, 'cnames'):
            cname: str
            for cname in hostnode.cnames:
                self.whois(cname, contact_email_only=False)
        self.whois(hostnode.name, contact_email_only=False)

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

    @overload
    def whois(self, query: str, contact_email_only: Literal[True]) -> list[str]:
        ...

    @overload
    def whois(self, query: str, contact_email_only: Literal[False]) -> str:
        ...

    @overload
    def whois(self, query: str, contact_email_only: bool) -> str | list[str]:
        ...

    def whois(self, query: str, contact_email_only: bool=False) -> str | list[str]:
        if not self.available:
            return ''

        bytes_whois = b''
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.server, self.port))
            sock.sendall(f'{query}\n'.encode())
            while True:
                data = sock.recv(2048)
                if not data:
                    break
                bytes_whois += data

        # if an abuse-c-Object is found in the whois entry, it will take precedence
        abuse_c = re.search(rb'abuse-c:\s+(.*)\s', bytes_whois)
        if abuse_c and abuse_c.lastindex:  # make sure we have a match and avoid exception on None or missing group 1
            # The whois entry has an abuse-c object
            _obj_name: str = abuse_c.group(1).decode()
            abuse_c_query = self.whois(_obj_name, contact_email_only)
            # The object exists
            if abuse_c_query and contact_email_only:
                # The object exists and we only want the email(s), the response is a list of emails
                return abuse_c_query
            elif abuse_c_query:
                # The object exists and we want the full whois entry, contatenate with a new line.
                # contact_email_only is False, so the response is a string, ignore the typing warning accordingy
                return '\n'.join([bytes_whois.decode(), abuse_c_query])  # type: ignore[list-item]
        # We either dont have an abuse-c object or it does not exist
        if not contact_email_only:
            return bytes_whois.decode()
        emails = list(set(re.findall(rb'[\w\.-]+@[\w\.-]+', bytes_whois)))
        return [e.decode() for e in sorted(emails)]
