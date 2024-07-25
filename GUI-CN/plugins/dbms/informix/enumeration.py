#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def searchDb(self):
        warnMsg = "在 Informix 上无法搜索数据库"
        logger.warning(warnMsg)

        return []

    def searchTable(self):
        warnMsg = "在 Informix 上无法搜索表"
        logger.warning(warnMsg)

        return []

    def searchColumn(self):
        warnMsg = "在 Informix 上无法搜索列"
        logger.warning(warnMsg)

        return []

    def search(self):
        warnMsg = "在 Informix 上不支持搜索选项"
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = "在 Informix 上无法枚举 SQL 语句"
        logger.warning(warnMsg)

        return []