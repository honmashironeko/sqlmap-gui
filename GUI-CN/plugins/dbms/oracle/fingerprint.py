#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import ORACLE_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.ORACLE)

    def getFingerprint(self):
        value = ""
        wsOsFp = Format.getOs("Web服务器", kb.headersFp)

        if wsOsFp:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("后端DBMS", kb.bannerFp)

            if dbmsOsFp:
                value += "%s\n" % dbmsOsFp

        value += "后端DBMS: "

        if not conf.extensiveFp:
            value += DBMS.ORACLE
            return value

        actVer = Format.getDbms()
        blank = " " * 15
        value += "主动指纹: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp.get("dbmsVersion")

            if banVer:
                banVer = Format.getDbms([banVer])
                value += "\n%s解析banner指纹: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%sHTML错误消息指纹: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        if not conf.extensiveFp and Backend.isDbmsWithin(ORACLE_ALIASES):
            setDbms(DBMS.ORACLE)

            self.getBanner()

            return True

        infoMsg = "测试 %s" % DBMS.ORACLE
        logger.info(infoMsg)

        # 注意:直接连接到Oracle数据库时,SELECT LENGTH(SYSDATE)=LENGTH(SYSDATE) FROM DUAL 不起作用
        if conf.direct:
            result = True
        else:
            result = inject.checkBooleanExpression("LENGTH(SYSDATE)=LENGTH(SYSDATE)")

        if result:
            infoMsg = "确认 %s" % DBMS.ORACLE
            logger.info(infoMsg)

            # 注意:直接连接到Oracle数据库时,SELECT NVL(RAWTOHEX([RANDNUM1]),[RANDNUM1])=RAWTOHEX([RANDNUM1]) FROM DUAL 不起作用
            if conf.direct:
                result = True
            else:
                result = inject.checkBooleanExpression("NVL(RAWTOHEX([RANDNUM1]),[RANDNUM1])=RAWTOHEX([RANDNUM1])")

            if not result:
                warnMsg = "后端DBMS不是 %s" % DBMS.ORACLE
                logger.warning(warnMsg)

                return False

            setDbms(DBMS.ORACLE)

            self.getBanner()

            if not conf.extensiveFp:
                return True

            infoMsg = "主动指纹识别 %s" % DBMS.ORACLE
            logger.info(infoMsg)

            # 参考:https://en.wikipedia.org/wiki/Oracle_Database
            for version in ("23c", "21c", "19c", "18c", "12c", "11g", "10g", "9i", "8i", "7"):
                number = int(re.search(r"([\d]+)", version).group(1))
                output = inject.checkBooleanExpression("%d=(SELECT SUBSTR((VERSION),1,%d) FROM SYS.PRODUCT_COMPONENT_VERSION WHERE ROWNUM=1)" % (number, 1 if number < 10 else 2))

                if output:
                    Backend.setVersion(version)
                    break

            return True
        else:
            warnMsg = "后端DBMS不是 %s" % DBMS.ORACLE
            logger.warning(warnMsg)

            return False

    def forceDbmsEnum(self):
        if conf.db:
            conf.db = conf.db.upper()

        if conf.tbl:
            conf.tbl = conf.tbl.upper()
