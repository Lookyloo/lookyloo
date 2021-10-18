#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class LookylooException(Exception):
    pass


class MissingEnv(LookylooException):
    pass


class CreateDirectoryException(LookylooException):
    pass


class ConfigError(LookylooException):
    pass
