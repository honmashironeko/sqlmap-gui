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
from lib.core.settings import METADB_SUFFIX
from lib.core.settings import RAIMA_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.RAIMA)

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
            value += DBMS.RAIMA
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
        if not conf.extensiveFp and Backend.isDbmsWithin(RAIMA_ALIASES):
            setDbms(DBMS.RAIMA)
            return True

        infoMsg = "测试 %s" % DBMS.RAIMA
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("ROWNUMBER()=ROWNUMBER()")

        if result:
            infoMsg = "确认 %s" % DBMS.RAIMA
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("INSSTR('[RANDSTR1]',0,0,'[RANDSTR2]') IS NOT NULL")

            if not result:
                warnMsg = "后端 DBMS 不是 %s" % DBMS.RAIMA
                logger.warning(warnMsg)

                return False

            setDbms(DBMS.RAIMA)

            return True
        else:
            warnMsg = "后端 DBMS 不是 %s" % DBMS.RAIMA
            logger.warning(warnMsg)

            return False

    def forceDbmsEnum(self):
        conf.db = ("%s%s" % (DBMS.RAIMA, METADB_SUFFIX)).replace(' ', '_')
