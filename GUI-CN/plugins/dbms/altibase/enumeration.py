#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getStatements(self):
        warnMsg = "在 Altibase 上无法枚举 SQL 语句"
        logger.warning(warnMsg)

        return []

    def getHostname(self):
        warnMsg = "在 Altibase 上无法枚举主机名"
        logger.warning(warnMsg)
