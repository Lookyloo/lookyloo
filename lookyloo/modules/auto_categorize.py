#!/usr/bin/env python3

from __future__ import annotations

from typing import Any, TYPE_CHECKING

import esprima  # type: ignore[import-untyped]

from .abstractmodule import AbstractModule


if TYPE_CHECKING:
    from ..lookyloo import Lookyloo
    from ..capturecache import CaptureCache


class AutoCategorize(AbstractModule):

    def module_init(self) -> bool:
        if not self.config.get('categories'):
            return False

        self.to_categorize: dict[str, dict[str, Any]] = {}

        # Filter out the ones that aren't enabled.
        for category, settings in self.config['categories'].items():
            if not settings.get('enabled'):
                continue
            self.to_categorize[category] = settings

        if self.to_categorize:
            # At lease one category is enabled
            return True
        return False

    def categorize(self, lookyloo: Lookyloo, capture: CaptureCache, /) -> None:
        for category, settings in self.to_categorize.items():
            if category == "invalid_init_script":
                if self._invalid_init_script(capture):
                    lookyloo.categorize_capture(capture.uuid, settings['tags'], as_admin=True)

    def _invalid_init_script(self, capture: CaptureCache, /) -> bool:
        """On the public instance, we have bots that submit sentences in the init_script
        field on the capture page. Most probably SEO scams, flagging them as such"""
        if not capture.capture_settings:
            return False

        if init_script := capture.capture_settings.init_script:
            try:
                esprima.parseScript(init_script)
                return False
            except Exception as e:
                # got an invalid init script
                self.logger.warning(f'[{capture.uuid}] Invalid init JS: {e}')
                return True
        return False
