#!/usr/bin/env python3

import logging

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

from ..default import get_config

logging.config.dictConfig(get_config('logging'))


class AbstractModule(ABC):
    '''Just a simple abstract for the modules to catch issues with initialization'''

    def __init__(self, /, *, config_name: Optional[str]=None,
                 config: Optional[Dict[str, Any]]=None):
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.config: Dict[str, Any] = {}
        self._available = False
        if config_name:
            try:
                self.config = get_config('modules', config_name)
            except Exception as e:
                self.logger.warning(f'Unable to get config for {config_name}: {e}')
                return
        elif config:
            self.config = config

        try:
            self._available = self.module_init()
        except Exception as e:
            self.logger.warning(f'Unable to initialize module: {e}.')

    @property
    def available(self) -> bool:
        return self._available

    @abstractmethod
    def module_init(self) -> bool:
        ...
