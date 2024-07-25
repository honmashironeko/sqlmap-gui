#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import singleTimeWarnMessage
from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getPasswordHashes(self):
        warnMsg = "在 Apache Derby 上无法枚举密码哈希值"
        logger.warning(warnMsg)

        return {}

    def getStatements(self):
        warnMsg = "在 Apache Derby 上无法枚举 SQL 语句"
        logger.warning(warnMsg)

        return []

    def getPrivileges(self, *args, **kwargs):
        warnMsg = "在 Apache Derby 上无法枚举用户权限"
        logger.warning(warnMsg)

        return {}

    def getRoles(self, *args, **kwargs):
        warnMsg = "在 Apache Derby 上无法枚举用户角色"
        logger.warning(warnMsg)

        return {}

    def getHostname(self):
        warnMsg = "在 Apache Derby 上无法枚举主机名"
        logger.warning(warnMsg)

    def getBanner(self):
        warnMsg = "在 Apache Derby 上无法枚举横幅信息"
        singleTimeWarnMessage(warnMsg)
