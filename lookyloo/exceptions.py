#!/usr/bin/env python3

from .default import LookylooException


class NoValidHarFile(LookylooException):
    """HAR file is invalid"""
    pass


class UnknownUUID(LookylooException):
    """The UUID is completely unknown"""
    pass


class DuplicateUUID(LookylooException):
    """UUID already exists"""
    pass


class MissingCaptureDirectory(LookylooException):
    """The capture directory doesn't exist on the disk"""
    pass


class TreeNeedsRebuild(LookylooException):
    """The pickle is missing, need to try a rebuild"""
    pass


class ModuleError(LookylooException):
    """Generic error when a module fails"""
    pass


class LacusUnreachable(LookylooException):
    """Cannot reach a Lacus instance"""
    pass


class LacusUnknown(LookylooException):
    """Attempt to connect to an unknown lacus instance"""
    pass


class LookylooPrivateCapture(LookylooException):
    """The capture is marked as private and cannot be accessed by a normal user"""
    pass


class UUIDMissingInCache(LookylooException):
    """The UUID is is missing in the cache (could be ongoing)"""
    pass


class NotCached(LookylooException):
    """The capture is not cached yet"""
    pass


class TreeBuildFailed(LookylooException):
    """Building the tree failed"""
    pass
