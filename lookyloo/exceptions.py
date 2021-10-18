#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .default import LookylooException


class NoValidHarFile(LookylooException):
    pass


class MissingUUID(LookylooException):
    pass


class MissingCaptureDirectory(LookylooException):
    pass


class TreeNeedsRebuild(LookylooException):
    pass
