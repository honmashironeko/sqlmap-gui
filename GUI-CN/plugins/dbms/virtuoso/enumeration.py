#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getPasswordHashes(self):
        warnMsg = "在Virtuoso上无法枚举用户密码哈希值"
        logger.warning(warnMsg)

        return {}

    def getPrivileges(self, *args, **kwargs):
        warnMsg = "在Virtuoso上无法枚举用户权限"
        logger.warning(warnMsg)

        return {}

    def getRoles(self, *args, **kwargs):
        warnMsg = "在Virtuoso上无法枚举用户角色"
        logger.warning(warnMsg)

        return {}

    def searchDb(self):
        warnMsg = "在Virtuoso上无法搜索数据库"
        logger.warning(warnMsg)

        return []

    def searchTable(self):
        warnMsg = "在Virtuoso上无法搜索表"
        logger.warning(warnMsg)

        return []

    def searchColumn(self):
        warnMsg = "在Virtuoso上无法搜索列"
        logger.warning(warnMsg)

        return []

    def search(self):
        warnMsg = "在Virtuoso上无法使用搜索选项"
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = "在Virtuoso上无法枚举SQL语句"
        logger.warning(warnMsg)

        return []
