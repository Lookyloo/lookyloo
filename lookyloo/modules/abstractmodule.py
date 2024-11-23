#!/usr/bin/env python3

from __future__ import annotations

import logging

from abc import ABC, abstractmethod
from typing import Any, TYPE_CHECKING

from ..default import get_config
if TYPE_CHECKING:
    from ..capturecache import CaptureCache

logging.config.dictConfig(get_config('logging'))


class AbstractModule(ABC):
    '''Just a simple abstract for the modules to catch issues with initialization'''

    def __init__(self, /, *, config_name: str | None=None,
                 config: dict[str, Any] | None=None) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.config: dict[str, Any] = {}
        self._available = False
        if config_name:
            try:
                self.config = get_config('modules', config_name)
            except Exception as e:
                self.logger.warning(f'Unable to get config for {config_name}: {e}')
                return
        elif config:
            self.config = config

        # Make all module admin only by default. It can be changed in the config file for each module.
        self._admin_only = bool(self.config.pop('admin_only', True))
        # Default keys in all the modules (if relevant)
        self._autosubmit = bool(self.config.pop('autosubmit', False))
        self._allow_auto_trigger = bool(self.config.pop('allow_auto_trigger', False))
        try:
            self._available = self.module_init()
        except Exception as e:
            self.logger.warning(f'Unable to initialize module: {e}.')

    @property
    def admin_only(self) -> bool:
        return self._admin_only

    @property
    def autosubmit(self) -> bool:
        return self._autosubmit

    @property
    def allow_auto_trigger(self) -> bool:
        return self._allow_auto_trigger

    @property
    def available(self) -> bool:
        return self._available

    @abstractmethod
    def module_init(self) -> bool:
        ...

    def capture_default_trigger(self, cache: CaptureCache, /, *, force: bool,
                                auto_trigger: bool, as_admin: bool) -> dict[str, str]:
        if not self.available:
            return {'error': 'Module not available'}
        if auto_trigger and not self.allow_auto_trigger:
            return {'error': 'Auto trigger not allowed on module'}
        if self.admin_only and not as_admin:
            return {'error': 'Admin only module'}
        return {}
