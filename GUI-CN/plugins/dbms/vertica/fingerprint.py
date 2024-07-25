#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import VERTICA_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.VERTICA)

    def getFingerprint(self):
        value = ""
        wsOsFp = Format.getOs("Web服务器", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("后端数据库管理系统", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value += "后端数据库管理系统: "

        if not conf.extensiveFp:
            value += DBMS.VERTICA
            return value

        actVer = Format.getDbms()
        blank = " " * 15
        value += "活动指纹: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp.get("dbmsVersion")

            if banVer:
                banVer = Format.getDbms([banVer])
                value += "\n%sbanner解析指纹: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%sHTML错误消息指纹: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if not conf.extensiveFp and Backend.isDbmsWithin(VERTICA_ALIASES):
            setDbms(DBMS.VERTICA)

            self.getBanner()

            return True

        infoMsg = "正在测试 %s" % DBMS.VERTICA
        logger.info(infoMsg)

        # NOTE: Vertica works too without the CONVERT_TO()
        result = inject.checkBooleanExpression("BITSTRING_TO_BINARY(NULL) IS NULL")

        if result:
            infoMsg = "确认 %s" % DBMS.VERTICA
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("HEX_TO_INTEGER(NULL) IS NULL")

            if not result:
                warnMsg = "后端数据库管理系统不是 %s" % DBMS.VERTICA
                logger.warning(warnMsg)

                return False

            setDbms(DBMS.VERTICA)

            self.getBanner()

            if not conf.extensiveFp:
                return True

            infoMsg = "正在主动指纹识别 %s" % DBMS.VERTICA
            logger.info(infoMsg)

            if inject.checkBooleanExpression("CALENDAR_HIERARCHY_DAY(NULL) IS NULL"):
                Backend.setVersion(">= 9.0")
            else:
                Backend.setVersion("< 9.0")

            return True
        else:
            warnMsg = "后端数据库管理系统不是 %s" % DBMS.VERTICA
            logger.warning(warnMsg)

            return False