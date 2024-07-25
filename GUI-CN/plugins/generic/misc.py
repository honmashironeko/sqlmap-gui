#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import ntpath
import re

from lib.core.common import Backend
from lib.core.common import hashDBWrite
from lib.core.common import isStackingAvailable
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import posixToNtSlashes
from lib.core.common import readInput
from lib.core.common import singleTimeDebugMessage
from lib.core.common import unArrayizeValue
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import DBMS
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import OS
from lib.core.exception import SqlmapNoneDataException
from lib.request import inject

class Miscellaneous(object):
    """
    This class defines miscellaneous functionalities for plugins.
    """

    def __init__(self):
        pass

    def getRemoteTempPath(self):
        if not conf.tmpPath and Backend.isDbms(DBMS.MSSQL):
            debugMsg = "正在识别 Microsoft SQL Server 错误日志目录,sqlmap 将使用该目录存储带有命令输出的临时文件"
            logger.debug(debugMsg)

            _ = unArrayizeValue(inject.getValue("SELECT SERVERPROPERTY('ErrorLogFileName')", safeCharEncode=False))

            if _:
                conf.tmpPath = ntpath.dirname(_)

        if not conf.tmpPath:
            if Backend.isOs(OS.WINDOWS):
                if conf.direct:
                    conf.tmpPath = "%TEMP%"
                else:
                    self.checkDbmsOs(detailed=True)

                    if Backend.getOsVersion() in ("2000", "NT"):
                        conf.tmpPath = "C:/WINNT/Temp"
                    elif Backend.isOs("XP"):
                        conf.tmpPath = "C:/Documents and Settings/All Users/Application Data/Temp"
                    else:
                        conf.tmpPath = "C:/Windows/Temp"
            else:
                conf.tmpPath = "/tmp"

        if re.search(r"\A[\w]:[\/\\]+", conf.tmpPath, re.I):
            Backend.setOs(OS.WINDOWS)

        conf.tmpPath = normalizePath(conf.tmpPath)
        conf.tmpPath = ntToPosixSlashes(conf.tmpPath)

        singleTimeDebugMessage("将使用 '%s' 作为临时文件目录" % conf.tmpPath)

        hashDBWrite(HASHDB_KEYS.CONF_TMP_PATH, conf.tmpPath)

        return conf.tmpPath

    def getVersionFromBanner(self):
        if "dbmsVersion" in kb.bannerFp:
            return

        infoMsg = "从后端 DBMS 的标语中检测版本"
        logger.info(infoMsg)

        query = queries[Backend.getIdentifiedDbms()].banner.query

        if conf.direct:
            query = "SELECT %s" % query

        kb.bannerFp["dbmsVersion"] = unArrayizeValue(inject.getValue(query)) or ""

        match = re.search(r"\d[\d.-]*", kb.bannerFp["dbmsVersion"])
        if match:
            kb.bannerFp["dbmsVersion"] = match.group(0)

    def delRemoteFile(self, filename):
        if not filename:
            return

        self.checkDbmsOs()

        if Backend.isOs(OS.WINDOWS):
            filename = posixToNtSlashes(filename)
            cmd = "del /F /Q %s" % filename
        else:
            cmd = "rm -f %s" % filename

        self.execCmd(cmd, silent=True)

    def createSupportTbl(self, tblName, tblField, tblType):
        inject.goStacked("DROP TABLE %s" % tblName, silent=True)

        if Backend.isDbms(DBMS.MSSQL) and tblName == self.cmdTblName:
            inject.goStacked("CREATE TABLE %s(id INT PRIMARY KEY IDENTITY, %s %s)" % (tblName, tblField, tblType))
        else:
            inject.goStacked("CREATE TABLE %s(%s %s)" % (tblName, tblField, tblType))

    def cleanup(self, onlyFileTbl=False, udfDict=None, web=False):
        """
        清理文件系统和数据库中的 sqlmap 创建的文件、表和函数
        """

        if web and self.webBackdoorFilePath:
            logger.info("清理上传的 Web 文件")

            self.delRemoteFile(self.webStagerFilePath)
            self.delRemoteFile(self.webBackdoorFilePath)

        if (not isStackingAvailable() or kb.udfFail) and not conf.direct:
            return

        if any((conf.osCmd, conf.osShell)) and Backend.isDbms(DBMS.PGSQL) and kb.copyExecTest:
            return

        if Backend.isOs(OS.WINDOWS):
            libtype = "动态链接库"

        elif Backend.isOs(OS.LINUX):
            libtype = "共享对象"

        else:
            libtype = "共享库"

        if onlyFileTbl:
            logger.debug("清理数据库管理系统")
        else:
            logger.info("清理数据库管理系统")

        logger.debug("删除支持表")
        inject.goStacked("DROP TABLE %s" % self.fileTblName, silent=True)
        inject.goStacked("DROP TABLE %shex" % self.fileTblName, silent=True)

        if not onlyFileTbl:
            inject.goStacked("DROP TABLE %s" % self.cmdTblName, silent=True)

            if Backend.isDbms(DBMS.MSSQL):
                udfDict = {"master..new_xp_cmdshell": {}}

            if udfDict is None:
                udfDict = getattr(self, "sysUdfs", {})

            for udf, inpRet in udfDict.items():
                message = "是否要删除 UDF '%s'？[Y/n] " % udf

                if readInput(message, default='Y', boolean=True):
                    dropStr = "DROP FUNCTION %s" % udf

                    if Backend.isDbms(DBMS.PGSQL):
                        inp = ", ".join(i for i in inpRet["input"])
                        dropStr += "(%s)" % inp

                    logger.debug("删除 UDF '%s'" % udf)
                    inject.goStacked(dropStr, silent=True)

            logger.info("数据库管理系统清理完成")

            warnMsg = "请记住 UDF %s 文件" % libtype

            if conf.osPwn:
                warnMsg += "和临时文件夹中的 Metasploit 相关文件"

            warnMsg += "只能手动删除"
            logger.warning(warnMsg)

    def likeOrExact(self, what):
        message = "sqlmap 是否要将提供的 %s 视为:\n" % what
        message += "[1] LIKE %s 名称(默认)\n" % what
        message += "[2] 精确 %s 名称" % what

        choice = readInput(message, default='1')

        if not choice or choice == '1':
            choice = '1'
            condParam = " LIKE '%%%s%%'"
        elif choice == '2':
            condParam = "='%s'"
        else:
            errMsg = "无效的值"
            raise SqlmapNoneDataException(errMsg)

        return choice, condParam
