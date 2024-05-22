#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import FORK
from lib.core.enums import HASHDB_KEYS
from lib.core.session import setDbms
from lib.core.settings import CACHE_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.CACHE)

    def getFingerprint(self):
        fork = hashDBRetrieve(HASHDB_KEYS.DBMS_FORK)

        if fork is None:
            if inject.checkBooleanExpression("$ZVERSION LIKE '%IRIS%'"):
                fork = FORK.IRIS
            else:
                fork = ""

            hashDBWrite(HASHDB_KEYS.DBMS_FORK, fork)

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
            value += DBMS.CACHE
            if fork:
                value += " (%s fork)" % fork
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

        if fork:
            value += "\n%sfork fingerprint: %s" % (blank, fork)

        return value

    def checkDbms(self):
        if not conf.extensiveFp and Backend.isDbmsWithin(CACHE_ALIASES):
            setDbms(DBMS.CACHE)

            self.getBanner()

            return True

        infoMsg = "正在测试 %s" % DBMS.CACHE
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("$LISTLENGTH(NULL) IS NULL")

        if result:
            infoMsg = "确认 %s" % DBMS.CACHE
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("%EXTERNAL %INTERNAL NULL IS NULL")

            if not result:
                warnMsg = "后端 DBMS 不是 %s" % DBMS.CACHE
                logger.warning(warnMsg)

                return False

            setDbms(DBMS.CACHE)

            self.getBanner()

            return True
        else:
            warnMsg = "后端 DBMS 不是 %s" % DBMS.CACHE
            logger.warning(warnMsg)

            return False

