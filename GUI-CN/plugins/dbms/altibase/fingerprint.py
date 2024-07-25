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
from lib.core.settings import ALTIBASE_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.ALTIBASE)

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
            value += DBMS.ALTIBASE
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
        if not conf.extensiveFp and Backend.isDbmsWithin(ALTIBASE_ALIASES):
            setDbms(DBMS.ALTIBASE)

            self.getBanner()

            return True

        infoMsg = "正在测试 %s" % DBMS.ALTIBASE
        logger.info(infoMsg)

        # Reference: http://support.altibase.com/fileDownload.do?gubun=admin&no=228
        result = inject.checkBooleanExpression("CHOSUNG(NULL) IS NULL")

        if result:
            infoMsg = "确认 %s" % DBMS.ALTIBASE
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("TDESENCRYPT(NULL,NULL) IS NULL")

            if not result:
                warnMsg = "后端 DBMS 不是 %s" % DBMS.ALTIBASE
                logger.warning(warnMsg)

                return False

            setDbms(DBMS.ALTIBASE)

            self.getBanner()

            return True
        else:
            warnMsg = "后端 DBMS 不是 %s" % DBMS.ALTIBASE
            logger.warning(warnMsg)

            return False
