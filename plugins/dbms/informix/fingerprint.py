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
from lib.core.settings import INFORMIX_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.INFORMIX)

    def getFingerprint(self):
        value = ""
        wsOsFp = Format.getOs("Web服务器", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("back-end DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value += "后端 DBMS: "

        if not conf.extensiveFp:
            value += DBMS.INFORMIX
            return value

        actVer = Format.getDbms()
        blank = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp.get("dbmsVersion")

            if banVer:
                banVer = Format.getDbms([banVer])
                value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if not conf.extensiveFp and Backend.isDbmsWithin(INFORMIX_ALIASES):
            setDbms(DBMS.INFORMIX)

            self.getBanner()

            return True

        infoMsg = "测试 %s" % DBMS.INFORMIX
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("[RANDNUM]=(SELECT [RANDNUM] FROM SYSMASTER:SYSDUAL)")

        if result:
            infoMsg = "确认 %s" % DBMS.INFORMIX
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("(SELECT DBINFO('DBNAME') FROM SYSMASTER:SYSDUAL) IS NOT NULL")

            if not result:
                warnMsg = "后端 DBMS 不是 %s" % DBMS.INFORMIX
                logger.warning(warnMsg)

                return False

            # 判断是否为 Informix >= 11.70
            if inject.checkBooleanExpression("CHR(32)=' '"):
                Backend.setVersion(">= 11.70")

            setDbms(DBMS.INFORMIX)

            self.getBanner()

            if not conf.extensiveFp:
                return True

            infoMsg = "主动指纹识别 %s" % DBMS.INFORMIX
            logger.info(infoMsg)

            for version in ("14.1", "12.1", "11.7", "11.5", "10.0"):
                output = inject.checkBooleanExpression("EXISTS(SELECT 1 FROM SYSMASTER:SYSDUAL WHERE DBINFO('VERSION,'FULL') LIKE '%%%s%%')" % version)

                if output:
                    Backend.setVersion(version)
                    break

            return True
        else:
            warnMsg = "后端 DBMS 不是 %s" % DBMS.INFORMIX
            logger.warning(warnMsg)

            return False