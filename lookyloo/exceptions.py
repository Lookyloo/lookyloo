#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class LookylooException(Exception):
    pass


class MissingEnv(LookylooException):
    pass


class NoValidHarFile(LookylooException):
    pass


class CreateDirectoryException(LookylooException):
    pass


class ConfigError(LookylooException):
    pass


class MissingUUID(LookylooException):
    pass


class MissingCaptureDirectory(LookylooException):
    pass


class TreeNeedsRebuild(LookylooException):
    pass
