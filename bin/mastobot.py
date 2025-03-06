#!/usr/bin/env python3

# Major parts of this code are based on the work of Stéphane Bortzmeyer on
# https://framagit.org/bortzmeyer/mastodon-DNS-bot

from __future__ import annotations

import logging
import re
import time

from lxml import html
from mastodon import Mastodon, MastodonError, StreamListener
from mastodon.return_types import Notification, Status
from pylookyloo import Lookyloo as PyLookyloo

from lookyloo.default import get_config, AbstractManager


class LookylooMastobotListener(StreamListener):

    def __init__(self, mastobot: Mastobot) -> None:
        self.mastobot = mastobot
        self.blocklist = self.mastobot.config.get('blocklist', [])
        # Avoid loops
        self.blocklist.append(f"{self.mastobot.config['botname']}@{self.mastobot.config['domain']}")

    def handle_heartbeat(self) -> None:
        self.mastobot.logger.debug("Heartbeat received")

    def on_update(self, status: Status) -> None:
        self.mastobot.logger.debug(f"Update: {status}")

    def on_notification(self, notification: Notification) -> None:
        self.mastobot.logger.debug(f"notification: {notification}")
        try:
            sender = None
            url_to_capture = None
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
                # Mastodon API returns the content of the toot in
                # HTML, just to make our lifes miserable
                doc = html.document_fromstring(notification['status']['content'])
                body = doc.text_content().strip()
                # The first word is the username, the rest is the URL
                _, url_to_capture = body.split(' ', 1)
                # TODO: do minimal validation to check if the URL is vaguely valid
                try:
                    permaurl = self.mastobot.lookyloo.submit(url=url_to_capture)
                except Exception as error:
                    self.mastobot.logger.error(f"Error while submitting {url_to_capture}: {error}")
                    return
                text = f'@{sender} Here is your capture: {permaurl}\n It may take a minute to complete, please be patient. #bot'
                self.mastobot.mastodon.status_post(text, in_reply_to_id=status_id, visibility=visibility, spoiler_text=spoiler_text)
            else:
                self.mastobot.logger.debug(f"Unhandled notification type: {notification['type']}")
            time.sleep(15)

        except KeyError as error:
            self.mastobot.logger.error(f"Malformed notification, missing {error}")
        except Exception as error:
            self.mastobot.logger.error(f"{sender} {url_to_capture} -> {error}")


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

        self.logger.setLevel(self.config.get('loglevel', 'DEBUG'))

        self.mastodon = Mastodon(api_base_url=self.config['domain'],
                                 access_token=self.config['access_token'],
                                 debug_requests=False)
        try:
            self.mastodon.account_verify_credentials()
        except MastodonError as e:
            self.logger.error(f"Error while verifying credentials: {e}")
            return
        lookyloo_url = get_config('generic', 'public_domain') if not self.config.get('remote_lookyloo') else self.config.get('remote_lookyloo')
        self.lookyloo = PyLookyloo(lookyloo_url)
        if not self.lookyloo.is_up:
            self.logger.error("Lookyloo is not reachable, aborting.")
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
                    self.logger.info("Stream is alive")
                if self.handler.is_receiving():
                    self.logger.info("Stream is receiving")

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
