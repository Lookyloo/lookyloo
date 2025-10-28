#!/usr/bin/env python3

from .default import LookylooException


class NoValidHarFile(LookylooException):
    pass


class MissingUUID(LookylooException):
    pass


class DuplicateUUID(LookylooException):
    pass


class MissingCaptureDirectory(LookylooException):
    pass


class TreeNeedsRebuild(LookylooException):
    pass


class ModuleError(LookylooException):
    pass


class LacusUnreachable(LookylooException):
    pass


class InvalidCaptureSetting(LookylooException):
    pass
