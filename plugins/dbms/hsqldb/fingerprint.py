#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.common import unArrayizeValue
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.session import setDbms
from lib.core.settings import HSQLDB_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.HSQLDB)

    def getFingerprint(self):
        value = ""
        wsOsFp = Format.getOs("web server", kb.headersFp)

        if wsOsFp and not conf.api:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("back-end DBMS", kb.bannerFp)

            if dbmsOsFp and not conf.api:
                value += "%s\n" % dbmsOsFp

        value += "后端 DBMS: "
        actVer = Format.getDbms()

        if not conf.extensiveFp:
            value += actVer
            return value

        blank = " " * 15
        value += "active fingerprint: %s" % actVer

        if kb.bannerFp:
            banVer = kb.bannerFp.get("dbmsVersion")

            if banVer:
                if re.search(r"-log$", kb.data.banner or ""):
                    banVer += ", logging enabled"

                banVer = Format.getDbms([banVer])
                value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        """
        参考指纹:
        DATABASE_VERSION()
        版本 2.2.6 添加了两个参数的 REPLACE 函数 REPLACE('a','a') 与 REPLACE('a','a','d') 的比较
        版本 2.2.5 添加了 SYSTIMESTAMP 函数
        版本 2.2.3 添加了 REGEXPR_SUBSTRING 和 REGEXPR_SUBSTRING_ARRAY 函数
        版本 2.2.0 添加了对 ROWNUM() 函数的支持
        版本 2.1.0 添加了 MEDIAN 聚合函数
        版本 < 2.0.1 添加了对日期时间 ROUND 和 TRUNC 函数的支持
        版本 2.0.0 添加了 VALUES 支持
        版本 1.8.0.4 添加了 org.hsqldbdb.Library 函数,getDatabaseFullProductVersion 返回完整的版本字符串,包括第四位数字(例如 1.8.0.4)。
        版本 1.7.2 添加了 CASE 语句和 INFORMATION_SCHEMA

        """

        if not conf.extensiveFp and Backend.isDbmsWithin(HSQLDB_ALIASES):
            setDbms("%s %s" % (DBMS.HSQLDB, Backend.getVersion()))

            if Backend.isVersionGreaterOrEqualThan("1.7.2"):
                kb.data.has_information_schema = True

            self.getBanner()

            return True

        infoMsg = "测试 %s" % DBMS.HSQLDB
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("CASEWHEN(1=1,1,0)=1")

        if result:
            infoMsg = "确认 %s" % DBMS.HSQLDB
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("ROUNDMAGIC(PI())>=3")

            if not result:
                warnMsg = "后端 DBMS 不是 %s" % DBMS.HSQLDB
                logger.warning(warnMsg)

                return False
            else:
                result = inject.checkBooleanExpression("ZERO() IS 0")   # 注意:检查 H2 DBMS(共享大部分相同的函数)
                if result:
                    warnMsg = "后端 DBMS 不是 %s" % DBMS.HSQLDB
                    logger.warning(warnMsg)

                    return False

                kb.data.has_information_schema = True
                Backend.setVersion(">= 1.7.2")
                setDbms("%s 1.7.2" % DBMS.HSQLDB)

                banner = self.getBanner()
                if banner:
                    Backend.setVersion("= %s" % banner)
                else:
                    if inject.checkBooleanExpression("(SELECT [RANDNUM] FROM (VALUES(0)))=[RANDNUM]"):
                        Backend.setVersionList([">= 2.0.0", "< 2.3.0"])
                    else:
                        banner = unArrayizeValue(inject.getValue("\"org.hsqldbdb.Library.getDatabaseFullProductVersion\"()", safeCharEncode=True))
                        if banner:
                            Backend.setVersion("= %s" % banner)
                        else:
                            Backend.setVersionList([">= 1.7.2", "< 1.8.0"])

            return True
        else:
            warnMsg = "后端 DBMS 不是 %s" % DBMS.HSQLDB
            logger.warning(warnMsg)

            dbgMsg = "...或版本 < 1.7.2"
            logger.debug(dbgMsg)

            return False

    def getHostname(self):
        warnMsg = "在 HSQLDB 上无法枚举主机名"
        logger.warning(warnMsg)

    def checkDbmsOs(self, detailed=False):
        if Backend.getOs():
            infoMsg = "后端 DBMS 操作系统为 %s" % Backend.getOs()
            logger.info(infoMsg)
        else:
            self.userChooseDbmsOs()