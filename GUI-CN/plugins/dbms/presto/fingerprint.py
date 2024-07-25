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
from lib.core.settings import PRESTO_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.PRESTO)

    def getFingerprint(self):
        value = ""
        wsOsFp = Format.getOs("Web 服务器", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("后端 DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value += "后端 DBMS: "

        if not conf.extensiveFp:
            value += DBMS.PRESTO
            return value

        actVer = Format.getDbms()
        blank = " " * 15
        value += "主动指纹识别: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp.get("dbmsVersion")

            if banVer:
                banVer = Format.getDbms([banVer])
                value += "\n%s横幅解析指纹: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%sHTML 错误消息指纹: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if not conf.extensiveFp and Backend.isDbmsWithin(PRESTO_ALIASES):
            setDbms(DBMS.PRESTO)

            self.getBanner()

            return True

        infoMsg = "测试 %s" % DBMS.PRESTO
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("TO_BASE64URL(NULL) IS NULL")

        if result:
            infoMsg = "确认 %s" % DBMS.PRESTO
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("TO_HEX(FROM_HEX(NULL)) IS NULL")

            if not result:
                warnMsg = "后端 DBMS 不是 %s" % DBMS.PRESTO
                logger.warning(warnMsg)

                return False

            setDbms(DBMS.PRESTO)

            if not conf.extensiveFp:
                return True

            infoMsg = "主动指纹识别 %s" % DBMS.PRESTO
            logger.info(infoMsg)

            # 参考:https://prestodb.io/docs/current/release/release-0.200.html
            if inject.checkBooleanExpression("FROM_IEEE754_32(NULL) IS NULL"):
                Backend.setVersion(">= 0.200")
            # 参考:https://prestodb.io/docs/current/release/release-0.193.html
            elif inject.checkBooleanExpression("NORMAL_CDF(NULL,NULL,NULL) IS NULL"):
                Backend.setVersion(">= 0.193")
            # 参考:https://prestodb.io/docs/current/release/release-0.183.html
            elif inject.checkBooleanExpression("MAP_ENTRIES(NULL) IS NULL"):
                Backend.setVersion(">= 0.183")
            # 参考:https://prestodb.io/docs/current/release/release-0.171.html
            elif inject.checkBooleanExpression("CODEPOINT(NULL) IS NULL"):
                Backend.setVersion(">= 0.171")
            # 参考:https://prestodb.io/docs/current/release/release-0.162.html
            elif inject.checkBooleanExpression("XXHASH64(NULL) IS NULL"):
                Backend.setVersion(">= 0.162")
            # 参考:https://prestodb.io/docs/current/release/release-0.151.html
            elif inject.checkBooleanExpression("COSINE_SIMILARITY(NULL,NULL) IS NULL"):
                Backend.setVersion(">= 0.151")
            # 参考:https://prestodb.io/docs/current/release/release-0.143.html
            elif inject.checkBooleanExpression("TRUNCATE(NULL) IS NULL"):
                Backend.setVersion(">= 0.143")
            # 参考:https://prestodb.io/docs/current/release/release-0.137.html
            elif inject.checkBooleanExpression("BIT_COUNT(NULL,NULL) IS NULL"):
                Backend.setVersion(">= 0.137")
            # 参考:https://prestodb.io/docs/current/release/release-0.130.html
            elif inject.checkBooleanExpression("MAP_CONCAT(NULL,NULL) IS NULL"):
                Backend.setVersion(">= 0.130")
            # 参考:https://prestodb.io/docs/current/release/release-0.115.html
            elif inject.checkBooleanExpression("SHA1(NULL) IS NULL"):
                Backend.setVersion(">= 0.115")
            # 参考:https://prestodb.io/docs/current/release/release-0.100.html
            elif inject.checkBooleanExpression("SPLIT(NULL,NULL) IS NULL"):
                Backend.setVersion(">= 0.100")
            # 参考:https://prestodb.io/docs/current/release/release-0.70.html
            elif inject.checkBooleanExpression("GREATEST(NULL,NULL) IS NULL"):
                Backend.setVersion(">= 0.70")
            else:
                Backend.setVersion("< 0.100")

            return True
        else:
            warnMsg = "后端 DBMS 不是 %s" % DBMS.PRESTO
            logger.warning(warnMsg)

            return False

