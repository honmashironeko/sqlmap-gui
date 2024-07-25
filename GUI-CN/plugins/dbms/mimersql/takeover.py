#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
    def osCmd(self):
        errMsg = "在MimerSQL上无法执行命令"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osShell(self):
        errMsg = "在MimerSQL上无法执行命令"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osPwn(self):
        errMsg = "在MimerSQL上无法建立带外连接"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osSmb(self):
        errMsg = "在MimerSQL上无法建立带外连接"
        raise SqlmapUnsupportedFeatureException(errMsg)
