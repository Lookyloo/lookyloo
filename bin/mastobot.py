#!/usr/bin/env python3

# Major parts of this code are based on the work of Stéphane Bortzmeyer on
# https://framagit.org/bortzmeyer/mastodon-DNS-bot

from __future__ import annotations

import logging
import re
import time

from bs4 import BeautifulSoup
from defang import defang  # type: ignore[import-untyped]
from lxml import html
from mastodon import Mastodon, MastodonError, StreamListener
from mastodon.return_types import Notification, Status
from pylookyloo import Lookyloo as PyLookyloo

from lookyloo.default import get_config, AbstractManager


class LookylooMastobotListener(StreamListener):

    def __init__(self, mastobot: Mastobot) -> None:
        self.mastobot = mastobot
        self.blocklist = self.mastobot.config.get('blocklist', [])
        self.proxies: list[str] = []
        # Avoid loops
        self.blocklist.append(f"{self.mastobot.config['botname']}@{self.mastobot.config['domain']}")

    def handle_heartbeat(self) -> None:
        self.mastobot.logger.debug("Heartbeat received")
        if not self.mastobot.lookyloo.is_up:
            self.mastobot.logger.error("Lookyloo is not reachable")
            return

        # get the list of proxies available in the default remote lacus instance
        if remote_lacuses := self.mastobot.lookyloo.get_remote_lacuses():
            if isinstance(remote_lacuses, list):
                # We have more than one remote lacuses, get the default one
                for remote_lacus in remote_lacuses:
                    if (remote_lacus.get('is_up')
                            and remote_lacus.get('name') == self.mastobot.default_remote_lacus):
                        if proxies := remote_lacus.get('proxies'):
                            self.proxies = proxies.keys()
                            break
                        else:
                            self.mastobot.logger.info(f"No proxies available in {self.mastobot.default_remote_lacus}")
                            return
            else:
                if remote_lacuses.get('is_up'):
                    # We have only one remote lacuse, we will use it
                    if proxies := remote_lacuses.get('proxies'):
                        self.proxies = proxies.keys()
        if not self.proxies:
            self.mastobot.logger.info("No proxies available")
            return

        note = "Message me one or more URL(s), and I'll capture the page for you. \n \
                Go to the website for more capture settings."

        # Annoyingly enough, we **must** set all the fields even if we only want to update one of them.
        # And on top of that, we cannot just use the existing field as if it is a URL,
        # it will have been escaped, and we're going to re-escape it which will break the field.
        # Each field bust be set here.
        # The entries we have are:
        # 1. Public URL of he Lookyloo instance
        # 2. Proxies available for capturing
        # 3. Query format for the bot
        # 4. The repository of the project
        # Only trigger the update if the proxies have changed
        account_details = self.mastobot.mastodon.me()
        proxy_field_exists = False
        proxies_changed = False
        proxies_str = ', '.join(self.proxies)
        fields_to_submit = []
        if account_details.fields:
            for field in account_details.fields:
                if field['name'] == 'Proxies':
                    proxy_field_exists = True
                    if field['value'] != proxies_str:
                        proxies_changed = True
                        if proxies_str:
                            # Update the field with the list of proxies
                            fields_to_submit.append(("Proxies", proxies_str))
            if not proxy_field_exists:
                # Add the proxies field
                proxies_changed = True
                fields_to_submit.append(("Proxies", proxies_str))
        if proxies_changed:
            self.mastobot.logger.info("Proxies have changed, update the account fields")
            fields_to_submit.insert(0, ("Website", self.mastobot.lookyloo.root_url))
            fields_to_submit.insert(2, ("Query format (single URL only)", '(<Optional_Proxy_Name>) <URL>'))
            fields_to_submit.insert(3, ("Repository", "https://github.com/Lookyloo"))
            self.mastobot.mastodon.account_update_credentials(note=note, fields=fields_to_submit)
        else:
            self.mastobot.logger.debug("Proxies have not changed, no need to update the account fields")

    def on_update(self, status: Status) -> None:
        self.mastobot.logger.debug(f"Update: {status}")

    def _find_url(self, content: str) -> list[str] | list[tuple[str, str]]:
        # Case 1, the toot has 2 words, the first is the username, the second is the URL
        doc = html.document_fromstring(content)
        body = doc.text_content().strip()
        splitted = body.split(' ')
        if len(splitted) == 2:
            # The first word is the username, the rest is the URL
            return [splitted[1]]
        elif len(splitted) == 3 and splitted[1] in self.proxies:
            # The first word is the username, the second is the proxy, the third is the URL
            return [(splitted[2], splitted[1])]

        # Case 2: we get all the hyperlinks in the toot (except the ones pointing to users)
        to_return = []
        soup = BeautifulSoup(content, 'lxml')
        for link in soup.find_all('a', href=True):
            if 'mention' in link.get('class', []):
                # usernames
                continue
            if link.get('href'):
                to_return.append(link['href'])
        return to_return

    def on_notification(self, notification: Notification) -> None:
        self.mastobot.logger.debug(f"notification: {notification}")
        try:
            sender = None
            visibility = None
            spoiler_text = None
            if notification['type'] == 'mention':
                status_id = notification['status']['id']
                sender = notification['account']['acct']
                if sender in self.blocklist:
                    self.mastobot.logger.info(f"Service refused to {sender}")
                    return
                match = re.match(r"^.*@(.*)$", sender)
                if match:
                    sender_domain = match.group(1)
                    if sender_domain in self.blocklist:
                        self.mastobot.logger.info(f"Service refused to {sender}")
                        return
                else:
                    # Probably local instance, without a domain name. Note that we cannot block local users.
                    if sender == self.mastobot.config['botname']:
                        self.mastobot.logger.info("Loop detected, sender is myself")
                        return
                visibility = notification['status']['visibility']
                spoiler_text = notification['status']['spoiler_text']
                for _url in self._find_url(notification['status']['content']):
                    if isinstance(_url, tuple):
                        # We have a tuple, the first element is the URL, the second is the proxy
                        url, proxy = _url
                        self.mastobot.logger.info(f"Using proxy {proxy} for {url}")
                    else:
                        # We just have a URL
                        url = _url
                        proxy = None
                        self.mastobot.logger.info(f"URL: {url}")
                    if not url:
                        continue
                    try:
                        permaurl = self.mastobot.lookyloo.submit(url=url, proxy=proxy)
                    except Exception as error:
                        self.mastobot.logger.error(f"Error while submitting {url}: {error}")
                        return
                    text = f'@{sender} Here is your capture of {defang(url)}: {permaurl}'
                    if proxy:
                        text += f' (using proxy: {proxy}).'
                    text += '\n It may take a minute to complete, please be patient. #bot'
                    self.mastobot.mastodon.status_post(text, in_reply_to_id=status_id, visibility=visibility, spoiler_text=spoiler_text)
            else:
                self.mastobot.logger.debug(f"Unhandled notification type: {notification['type']}")
            time.sleep(15)

        except KeyError as error:
            self.mastobot.logger.error(f"Malformed notification, missing {error}")
        except Exception as error:
            self.mastobot.logger.error(f"{sender} -> {error}")


class Mastobot(AbstractManager):

    def __init__(self, loglevel: int | None=None) -> None:
        super().__init__(loglevel)
        self.script_name = 'mastobot'

        self.ready = False
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        try:
            self.config = get_config('mastobot')
        except Exception as e:
            self.logger.error(f"Error while loading the configuration: {e}")
            return

        if self.config['enable'] is False:
            self.logger.info("Mastobot is disabled, aborting.")
            return

        self.logger.setLevel(self.config.get('loglevel', 'INFO'))

        lookyloo_url = get_config('generic', 'public_domain') if not self.config.get('remote_lookyloo') else self.config.get('remote_lookyloo')
        self.lookyloo = PyLookyloo(lookyloo_url)
        if not self.lookyloo.is_up:
            self.logger.error("Lookyloo is not reachable, aborting.")
            return

        if get_config('generic', 'multiple_remote_lacus').get('enable'):
            # Multiple remote lacus are enabled, we will use the default one for the proxies
            self.default_remote_lacus = get_config('generic', 'multiple_remote_lacus').get('default')
        else:
            self.default_remote_lacus = 'default'

        self.mastodon = Mastodon(api_base_url=f"https://{self.config['domain']}",
                                 access_token=self.config['access_token'],
                                 debug_requests=False)
        try:
            self.mastodon.account_verify_credentials()
        except MastodonError as e:
            self.logger.error(f"Error while verifying credentials: {e}")
            return

        if not self.mastodon.stream_healthy():
            self.logger.error("Stream is unhealthy, aborting.")
            return

        self.listener = LookylooMastobotListener(self)
        self.ready = True
        self.handler = None

    def _to_run_forever(self) -> None:
        if not self.handler:
            self.handler = self.mastodon.stream_user(LookylooMastobotListener(self), timeout=30, reconnect_async=True, run_async=True)
        else:
            if self.force_stop:
                self.logger.info("Force stop requested")
                self.handler.close()
                self.handler = None
            else:
                if self.handler.is_alive():
                    self.logger.debug("Stream is alive")
                if self.handler.is_receiving():
                    self.logger.debug("Stream is receiving")

    def _wait_to_finish(self) -> None:
        if self.handler:
            self.handler.close()
            self.handler = None


def main() -> None:
    bot = Mastobot()
    if bot.ready:
        bot.run(sleep_in_sec=10)


if __name__ == '__main__':
    main()
