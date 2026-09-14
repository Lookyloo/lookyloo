#!/usr/bin/env python3

from __future__ import annotations

import json
import logging
import logging.config

from collections import Counter
from datetime import date, timedelta, datetime
from typing import Any
from urllib.parse import urlparse

from lacuscore import CaptureStatus as CaptureStatusCore
from lookyloo import Lookyloo
from lookyloo_models import LookylooCaptureSettings
from lookyloo.exceptions import LacusUnreachable, LacusUnknown, NotCached
from lookyloo.default import AbstractManager, get_config, get_homedir, safe_create_dir
from lookyloo.helpers import ParsedUserAgent, serialize_to_json, LookylooCacheLogAdapter
from lookyloo.modules import AIL, AssemblyLine, MISP, AutoCategorize, OnionLookup
from pylacus import CaptureStatus as CaptureStatusPy

logging.config.dictConfig(get_config('logging'))


class Processing(AbstractManager):

    def __init__(self, loglevel: int | None=None):
        super().__init__(loglevel)
        self.script_name = 'processing'
        self.lookyloo = Lookyloo()

        self.use_own_ua = get_config('generic', 'use_user_agents_users')

        self.auto_categorize = AutoCategorize(config_name='AutoCategorize')
        self.ail = AIL()
        self.onion_lookup = OnionLookup()
        self.assemblyline = AssemblyLine(config_name='AssemblyLine')
        self.misps = self.lookyloo.misps
        # prepare list of MISPs to auto-push to (if any)
        self.misps_auto_push: dict[str, MISP] = {}
        if self.misps.available:
            self.misps_auto_push = {name: connector for name, connector in self.misps.items()
                                    if all([connector.available, connector.enable_push, connector.auto_push])}

    def _to_run_forever(self) -> None:
        if self.use_own_ua:
            self._build_ua_file()
        self.logger.debug('Update recent captures.')
        self._update_recent_captures()
        self.logger.debug('Retry failed queue.')
        self._retry_failed_enqueue()
        self.logger.debug('Build captures.')
        self._process_built_captures()
        self.logger.debug('Done.')

    def _update_recent_captures(self) -> None:
        if not self.lookyloo.redis.exists('recent_captures_public'):
            # recent_captures_public is a new key, if it doesnt exist, remove recent_captures to retrigger it
            self.lookyloo.redis.delete('recent_captures')
        p = self.lookyloo.redis.pipeline()
        i = 0
        __counter_shutdown_force = 0
        for uuid, directory in self.lookyloo.redis.hscan_iter('lookup_dirs'):
            __counter_shutdown_force += 1
            if __counter_shutdown_force % 1000 == 0 and self.shutdown_requested():
                self.logger.warning('Shutdown requested, breaking.')
                break

            if self.lookyloo.redis.zscore('recent_captures', uuid) is not None:
                # the UUID is already in the recent captures
                continue

            try:
                cache = self.lookyloo.capture_cache(uuid, quick=True)
            except NotCached:
                continue
            # we do not want this method to build the pickle, **but** if the pickle exists
            # AND the capture isn't in the cache, we want to add it
            if not hasattr(cache, 'timestamp') or not cache.timestamp:
                continue
            i += 1
            p.zadd('recent_captures', mapping={uuid: cache.timestamp.timestamp()})
            if not cache.no_index and not cache.private:
                p.zadd('recent_captures_public', mapping={uuid: cache.timestamp.timestamp()})

            if i % 100 == 0:
                # Avoid huge pipeline on initialization
                p.execute()
                self.logger.debug('Update recent captures...')
                p = self.lookyloo.redis.pipeline()
        p.execute()

    def _build_ua_file(self) -> None:
        '''Build a file in a format compatible with the capture page'''
        yesterday = (date.today() - timedelta(days=1))
        self_generated_ua_file_path = get_homedir() / 'own_user_agents' / str(yesterday.year) / f'{yesterday.month:02}'
        safe_create_dir(self_generated_ua_file_path)
        self_generated_ua_file = self_generated_ua_file_path / f'{yesterday.isoformat()}.json'
        if self_generated_ua_file.exists():
            self.logger.debug(f'User-agent file for {yesterday} already exists.')
            return
        self.logger.info(f'Generating user-agent file for {yesterday}')
        entries = self.lookyloo.redis.zrevrange(f'user_agents|{yesterday.isoformat()}', 0, -1)
        if not entries:
            self.logger.info(f'No User-agent file for {yesterday} to generate.')
            return

        to_store: dict[str, Any] = {'by_frequency': []}
        uas = Counter([entry.split('|', 1)[1] for entry in entries])
        for ua, _ in uas.most_common():
            parsed_ua = ParsedUserAgent(ua)
            if not parsed_ua.platform or not parsed_ua.browser:
                continue
            platform_key = parsed_ua.platform
            if parsed_ua.platform_version:
                platform_key = f'{platform_key} {parsed_ua.platform_version}'
            browser_key = parsed_ua.browser
            if parsed_ua.version:
                browser_key = f'{browser_key} {parsed_ua.version}'
            if platform_key not in to_store:
                to_store[platform_key] = {}
            if browser_key not in to_store[platform_key]:
                to_store[platform_key][browser_key] = set()
            to_store[platform_key][browser_key].add(parsed_ua.string)
            to_store['by_frequency'].append({'os': platform_key,
                                             'browser': browser_key,
                                             'useragent': parsed_ua.string})
        with self_generated_ua_file.open('w') as f:
            json.dump(to_store, f, indent=2, default=serialize_to_json)

        # Remove the UA / IP mapping.
        self.lookyloo.redis.delete(f'user_agents|{yesterday.isoformat()}')
        self.logger.info(f'User-agent file for {yesterday} generated.')

    def _retry_failed_enqueue(self) -> None:
        '''If enqueuing failed, the settings are added, with a UUID in the 'to_capture key', and they have a UUID'''
        to_requeue: list[LookylooCaptureSettings] = []
        for uuid in self.lookyloo.redis.zrevrangebyscore('to_capture', 'Inf', '-Inf', start=0, num=500):
            logger = LookylooCacheLogAdapter(self.logger, {'uuid': uuid})
            if not self.lookyloo.redis.exists(uuid):
                logger.warning('The settings are missing, there is nothing we can do.')
                self.lookyloo.redis.zrem('to_capture', uuid)
                continue
            if self.lookyloo.redis.sismember('ongoing', uuid):
                # Finishing up on lookyloo side, ignore.
                continue

            try:
                capture_settings = self.lookyloo.get_settings_to_capture(uuid)
            except Exception as e:
                logger.warning(f'Settings are broken, clearing them up: {e}.')
                self.lookyloo.redis.delete(uuid)
                continue

            if not capture_settings:
                logger.warning('Unable to get settings from redis, skip.')
                continue

            if not self.lookyloo.redis.hexists(uuid, 'uuid'):
                # old format, hset didn't contain the uuid
                self.lookyloo.redis.hset(uuid, 'uuid', uuid)

            try:
                if self.lookyloo.get_lacus_capture_status(capture_settings) in [CaptureStatusPy.UNKNOWN, CaptureStatusCore.UNKNOWN]:
                    # The capture is unknown on lacus side, but we have it in the to_capture queue *and* we still have the settings on lookyloo side
                    if capture_settings.not_queued:
                        # The capture has already been marked as not queued
                        to_requeue.append(capture_settings)
                    else:
                        # It might be a race condition so we don't add it in the requeue immediately, just flag it at not_queued.
                        self.lookyloo.redis.hset(uuid, 'not_queued', 1)
            except LacusUnknown as e:
                logger.warning(f'Unknown lacus, revert to default: {e}')
                self.lookyloo.redis.hset(uuid, 'remote_lacus_name', self.lookyloo.default_lacus)
                continue
            except LacusUnreachable:
                logger.warning('Lacus unreachable, trying again later')
                break

            if len(to_requeue) > 100:
                # Enough stuff to requeue
                self.logger.info('Got enough captures to requeue.')
                break

        for capture_settings in to_requeue:
            if not capture_settings.uuid:
                self.logger.warning('Missing UUID, should not happen there.')
                continue
            logger = LookylooCacheLogAdapter(self.logger, {'uuid': capture_settings.uuid})
            if self.lookyloo.redis.zscore('to_capture', capture_settings.uuid) is None:
                # The capture has been captured in the meantime.
                continue
            logger.info('Non-queued capture, retrying now.')
            try:
                new_uuid, _ = self.lookyloo.enqueue_capture(capture_settings, source='api', user='background_processing',
                                                            authenticated=False, seed_expire=None)
                if new_uuid != capture_settings.uuid:
                    # somehow, between the check and queuing, the UUID isn't UNKNOWN anymore, just checking that
                    logger.warning(f'Had to change the capture UUID (duplicate). New: {new_uuid}')
                    # also need to clear up the old capture settings, as it won't be processed
                    self.lookyloo.redis.zrem('to_capture', capture_settings.uuid)
                    self.lookyloo.redis.delete(capture_settings.uuid)
                    continue
            except LacusUnreachable:
                logger.warning('Lacus still unreachable.')
                break
            except Exception as e:
                logger.warning(f'Still unable to enqueue capture: {e}')
                break
            else:
                self.lookyloo.redis.hdel(capture_settings.uuid, 'not_queued')
                logger.info('Queueing successfull.')

    def _process_built_captures(self) -> None:
        """This method triggers some post processing on recent built captures.
        We do not want to duplicate the background build script here.
        """

        if not any([self.onion_lookup.available, self.ail.available, self.assemblyline.available,
                    self.misps_auto_push, self.auto_categorize.available]):
            return

        # Just check the captures of the last day
        delta_to_process = timedelta(days=1)
        cut_time = datetime.now() - delta_to_process
        # Just to make sure it expires after the delta
        redis_expire = int(delta_to_process.total_seconds()) + 300

        # AL notification queue is returning all the entries in the queue
        if self.assemblyline.available:
            for entry in self.assemblyline.get_notification_queue():
                if current_uuid := entry['submission']['metadata'].get('lookyloo_uuid'):
                    if cached := self.lookyloo.capture_cache(current_uuid):
                        self.logger.debug(f'Found AssemblyLine response for {cached.uuid}: {entry}')
                        self.logger.debug(f'Ingest ID: {entry["ingest_id"]}, UUID: {entry["submission"]["metadata"]["lookyloo_uuid"]}')
                        with (cached.capture_dir / 'assemblyline_ingest.json').open('w') as f:
                            f.write(json.dumps(entry, indent=2, default=serialize_to_json))

        __counter_shutdown_force = 0
        for cached in self.lookyloo.sorted_capture_cache(index_cut_time=cut_time, public=False):
            if cached.error:
                continue
            __counter_shutdown_force += 1
            if __counter_shutdown_force % 1000 == 0 and self.shutdown_requested():
                self.logger.warning('Shutdown requested, breaking.')
                break
            logger = LookylooCacheLogAdapter(self.logger, {'uuid': cached.uuid})
            # NOTE: categorization must be first as the tags could be submitted to MISP
            # 2026-03-17: and they're optionally used for MISP autopush
            if self.auto_categorize.available and not self.lookyloo.redis.exists(f'auto_categorize|{cached.uuid}'):
                self.lookyloo.redis.setex(f'auto_categorize|{cached.uuid}', redis_expire, 1)
                self.auto_categorize.categorize(self.lookyloo, cached)
                logger.debug('Auto categorize done.')

            # NOTE: onion lookup must be processed first as it might update the categories
            if self.onion_lookup and not self.lookyloo.redis.exists(f'bg_processed_onion_lookup|{cached.uuid}'):
                self.lookyloo.redis.setex(f'bg_processed_onion_lookup|{cached.uuid}', redis_expire, 1)
                try:
                    if lookups := self.onion_lookup.lookup(cached):
                        self.lookyloo.change_visibility(cached.uuid, visibility='private')
                        for hostname, lookup in lookups.items():
                            if lookup and isinstance(lookup, dict) and 'tags' in lookup:
                                tags_to_add = [tag for tag in lookup['tags'] if tag.startswith('dark-web:topic')]
                                self.lookyloo.categorize_capture(cached.uuid, categories=tags_to_add, as_admin=True)
                    else:
                        # no onions in the redirects, do nothing
                        pass
                except Exception as e:
                    logger.error(f'Unable to query onion lookup: {e}')

            if self.ail.available and not self.lookyloo.redis.exists(f'bg_processed_ail|{cached.uuid}'):
                self.lookyloo.redis.setex(f'bg_processed_ail|{cached.uuid}', redis_expire, 1)
                ail_response = {}
                for redirect in cached.redirects:
                    parsed = urlparse(redirect)
                    if parsed.hostname and parsed.hostname.endswith('.onion'):
                        try:
                            ail_response = self.ail.submit(self.lookyloo.lacus_export(cached.uuid))
                        except Exception as e:
                            logger.error(f'Unable to submit capture to AIL: {e}')
                        # got one, break
                        break

                if ail_response:
                    # Submit onions captures to AIL
                    if ail_response.get('error'):
                        if isinstance(ail_response['error'], str):
                            # general error, the module isn't available
                            logger.error(f'Unable to submit capture to AIL: {ail_response["error"]}')
                        elif isinstance(ail_response['error'], list):
                            # Errors when submitting individual URLs
                            for error in ail_response['error']:
                                logger.warning(error)
                    elif uuid := ail_response.get('uuid'):
                        # if we have successful submissions, we may want to get the references later.
                        # Store in redis for now.
                        logger.info(f'Capture submitted to AIL ({uuid}).')
                        self.lookyloo.redis.hset(f'bg_processed_ail|{cached.uuid}|refs', mapping=ail_response)
                        self.lookyloo.redis.expire(f'bg_processed_ail|{cached.uuid}|refs', redis_expire)
                    logger.debug('AIL processing done.')

            if self.assemblyline.available and not self.lookyloo.redis.exists(f'bg_processed_assemblyline|{cached.uuid}'):
                logger.debug(f'Processing AssemblyLine now. --- Available: {self.assemblyline.available}')
                self.lookyloo.redis.setex(f'bg_processed_assemblyline|{cached.uuid}', redis_expire, 1)

                # Submit URLs to AssemblyLine
                al_response = self.assemblyline.capture_default_trigger(cached, force=False,
                                                                        auto_trigger=True, as_admin=True)
                if not al_response.get('error') and not al_response.get('success'):
                    logger.debug('Nothing to submit, skip')
                elif al_response.get('error'):
                    if isinstance(al_response['error'], str):
                        # general error, the module isn't available
                        logger.error(f'Unable to submit capture to AssemblyLine: {al_response["error"]}')
                    elif isinstance(al_response['error'], list):
                        # Errors when submitting individual URLs
                        for error in al_response['error']:
                            logger.warning(error)
                elif al_response.get('success'):
                    # if we have successful submissions, save the response for later.
                    logger.info('URLs submitted to AssemblyLine.')
                    logger.debug(f'Response: {al_response["success"]}')

                logger.info('AssemblyLine submission processing done.')

            # if one of the MISPs has autopush, and it hasn't been pushed yet, push it.
            for name, connector in self.misps_auto_push.items():
                if self.lookyloo.redis.exists(f'bg_processed_misp|{name}|{cached.uuid}'):
                    continue
                self.lookyloo.redis.setex(f'bg_processed_misp|{name}|{cached.uuid}', redis_expire, 1)
                # 2026-03-17: if auto_push_categories is None, push everything (historical config)
                # if it is a list of categories, only auto push the captures with these categories
                if connector.auto_push_categories is not None:
                    if not connector.auto_push_categories.intersection(cached.categories):
                        # no overlap, do not push
                        continue
                try:
                    # NOTE: is_public_instance set to True so we use the default distribution level
                    # from the instance
                    misp_event = self.misps.export(cached, is_public_instance=True)
                except Exception as e:
                    logger.error(f'Unable to create the MISP Event: {e}')
                    continue
                try:
                    misp_response = connector.push(misp_event, as_admin=True)
                except Exception as e:
                    logger.critical(f'Unable to push the MISP Event: {e}')
                    continue

                if isinstance(misp_response, dict):
                    if 'error' in misp_response:
                        logger.error(f'Error while pushing the MISP Event: {misp_response["error"]}')
                    else:
                        logger.error(f'Unexpected error while pushing the MISP Event: {misp_response}')
                else:
                    for event in misp_response:
                        logger.info(f'Successfully pushed event {event.uuid}')


def main() -> None:
    p = Processing()
    p.run(sleep_in_sec=60)


if __name__ == '__main__':
    main()
