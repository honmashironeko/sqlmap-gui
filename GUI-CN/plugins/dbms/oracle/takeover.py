#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.takeover import Takeover as GenericTakeover

class Takeover(GenericTakeover):
    def osCmd(self):
        errMsg = "尚未实现Oracle的操作系统命令执行功能"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osShell(self):
        errMsg = "尚未实现Oracle的操作系统Shell功能"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osPwn(self):
        errMsg = "尚未实现Oracle的操作系统外带控制功能"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def osSmb(self):
        errMsg = "尚未实现Oracle的一键操作系统外带控制功能"
        raise SqlmapUnsupportedFeatureException(errMsg)
