#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapUndefinedMethod

class Connector(object):
    """
    这个类为插件定义了通用的数据库管理系统协议功能。
    """

    def __init__(self):
        self.connector = None
        self.cursor = None
        self.hostname = None

    def initConnection(self):
        self.user = conf.dbmsUser or ""
        self.password = conf.dbmsPass or ""
        self.hostname = conf.hostname
        self.port = conf.port
        self.db = conf.dbmsDb

    def printConnected(self):
        if self.hostname and self.port:
            infoMsg = "连接到 %s 服务器 '%s:%d' 成功" % (conf.dbms, self.hostname, self.port)
            logger.info(infoMsg)

    def closed(self):
        if self.hostname and self.port:
            infoMsg = "连接到 %s 服务器 '%s:%d' 已关闭" % (conf.dbms, self.hostname, self.port)
            logger.info(infoMsg)

        self.connector = None
        self.cursor = None

    def initCursor(self):
        self.cursor = self.connector.cursor()

    def close(self):
        try:
            if self.cursor:
                self.cursor.close()
            if self.connector:
                self.connector.close()
        except Exception as ex:
            logger.debug(ex)
        finally:
            self.closed()

    def checkFileDb(self):
        if not os.path.exists(self.db):
            errMsg = "提供的数据库文件 '%s' 不存在" % self.db
            raise SqlmapFilePathException(errMsg)

    def connect(self):
        errMsg = "在具体的DBMS插件中必须定义 'connect' 方法"
        raise SqlmapUndefinedMethod(errMsg)

    def fetchall(self):
        errMsg = "在具体的DBMS插件中必须定义 'fetchall' 方法"
        raise SqlmapUndefinedMethod(errMsg)

    def execute(self, query):
        errMsg = "在具体的DBMS插件中必须定义 'execute' 方法"
        raise SqlmapUndefinedMethod(errMsg)

    def select(self, query):
        errMsg = "在具体的DBMS插件中必须定义 'select' 方法"
        raise SqlmapUndefinedMethod(errMsg)