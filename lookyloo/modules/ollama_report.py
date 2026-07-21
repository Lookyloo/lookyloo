#!/usr/bin/env python3

from __future__ import annotations

from typing import Any

import logging

from ollama import Client

from ..default import get_config, LookylooException
from ..helpers import get_useragent_for_requests, global_proxy_for_requests

# NOTE: it is slow, and hallucinate a lot, good luck.


class OllamaReport():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.config = get_config('modules', 'Ollama')
        self._enabled = True
        if not self.config.get('url'):
            self.logger.info('No URL in config.')
            self._enabled = False
        self.client = Client(host=self.config['url'],
                             headers={'user-agent': get_useragent_for_requests()},
                             mounts=global_proxy_for_requests())
        self.model = self.config['model']

    @property
    def available(self) -> bool:
        if not self._enabled:
            return False
        return True

    def get_report(self, ai_export: dict[str, Any]) -> str | None:
        '''Submit a AI export to Ollama and get the report.'''
        if not self.available:
            raise LookylooException('Ollama not available, probably not able to reach the server.')

        messages = [{"role": "system", "content": "You are an infosec analyst investigating websites. Describe your reasoning."}]
        if redirects := ai_export.get('redirects'):
            messages.append({"role": "user", "content": f"A chain of redirects to the screenshot submited next {redirects}"})
        if md := ai_export.get('html_as_markdown'):
            messages.append({"role": "user", "content": f"This is the HTML content of the rendered page turned into a markdown document\n {md}"})
        if s := ai_export.get('screenshot'):
            messages.append({"role": "user", "content": "what is this image?", "image": s})
        messages.append({"role": "user", "content": "What kind of website is it? Assign a MISP taxonomy."})
        response = self.client.chat(model=self.model, messages=messages)
        return response.message.content
