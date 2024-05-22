#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getDbs(self):
        warnMsg = "在 Firebird 上无法枚举数据库(仅使用 '--tables')"
        logger.warning(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = "在 Firebird 上无法枚举用户密码哈希值"
        logger.warning(warnMsg)

        return {}

    def searchDb(self):
        warnMsg = "在 Firebird 上无法搜索数据库"
        logger.warning(warnMsg)

        return []

    def getHostname(self):
        warnMsg = "在 Firebird 上无法枚举主机名"
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = "在 Firebird 上无法枚举 SQL 语句"
        logger.warning(warnMsg)

        return []